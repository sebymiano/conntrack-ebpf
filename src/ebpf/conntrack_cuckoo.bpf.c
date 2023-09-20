/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Part of the code has been taken and adapted from the Polycube project
 * (https://github.com/polycube-network/polycube) */

/* Copyright (c) 2017 The Polycube Authors */
/* Copyright (c) 2022 Sebastiano Miano <mianosebastiano@gmail.com> */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/if_vlan.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "cilium_builtin.h"

#include "conntrack_structs.h"
#include "conntrack_maps_v2.h"
#include "conntrack_bpf_log.h"
#include "conntrack_parser.h"

#include "cuckoo_hash.h"

extern __u32 LINUX_KERNEL_VERSION __kconfig;

#define CUCKOO_CONNTRACK_MAP_MAX_SIZE 128

BPF_CUCKOO_HASH(cuckoo_connections, struct ct_k, struct ct_v, CUCKOO_CONNTRACK_MAP_MAX_SIZE)

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
} __attribute__((packed));

struct flow_info {
    __u8 flags;
    __u32 seqN;
    __u32 ackN;
    __u64 timestamp;
} __attribute__((packed));

struct metadata_elem {
    struct flow_key flow;
    struct flow_info info;
} __attribute__((packed));

struct metadata_processing_loop_ctx {
    void *data;
    void *data_end;
    struct packetHeaders curr_pkt;
    __u16 nh_off;
    uint8_t curr_ipRev;
    uint8_t curr_portRev;
    struct ct_k curr_pkt_key;
    struct ct_v curr_value;
    struct ct_v *map_curr_value;
    struct cuckoo_connections_cuckoo_hash_map *cuckoo_map;
    int ret_code;
    uint32_t curr_value_set;
};

typedef enum return_action { 
    PASS_ACTION = 0, 
    PASS_ACTION_DEL_VALUE,
    TCP_NEW 
} return_action_t;

static __always_inline void conntrack_get_key(struct ct_k *key, const struct packetHeaders *pkt,
                                              uint8_t *ipRev, uint8_t *portRev) {
    if (pkt->srcIp == pkt->dstIp) {
        if (pkt->srcPort <= pkt->dstPort) {
            key->srcPort = pkt->srcPort;
            key->dstPort = pkt->dstPort;
            *portRev = 0;
            *ipRev = 0;
        } else {
            key->srcPort = pkt->dstPort;
            key->dstPort = pkt->srcPort;
            *portRev = 1;
            *ipRev = 1;
        }
    } else if (pkt->srcIp < pkt->dstIp) {
        key->srcIp = pkt->srcIp;
        key->dstIp = pkt->dstIp;
        key->srcPort = pkt->srcPort;
        key->dstPort = pkt->dstPort;
        *ipRev = 0;
        *portRev = 0;
    } else {
        key->srcIp = pkt->dstIp;
        key->dstIp = pkt->srcIp;
        key->srcPort = pkt->dstPort;
        key->dstPort = pkt->srcPort;
        *ipRev = 1;
        *portRev = 1;
    }

    key->l4proto = pkt->l4proto;
}

static return_action_t handle_tcp_conntrack(struct packetHeaders *pkt,
                                                            struct ct_v *ct_value,
                                                            uint64_t timestamp, bool reverse) {
    bpf_log_debug("Handling TCP conntrack. Current state: %u\n", ct_value->state);
    bpf_log_debug("Reverse: %d\n", reverse);
    if (ct_value->state == SYN_SENT) {
        bpf_log_debug("Received packet in SYN_SENT state\n");
        if (!reverse) {
            // Still haven't received a SYN,ACK To the SYN
            if ((pkt->flags & TCPHDR_SYN) != 0 && (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
                // Another SYN. It is valid, probably a retransmission.
                ct_value->ttl = timestamp + TCP_SYN_SENT;
                return PASS_ACTION;
            }
        } else {
            bpf_log_debug("pkt ackN: %u\n", pkt->ackN);
            bpf_log_debug("ct_value sequence: %u\n", ct_value->sequence);
            // This should be a SYN, ACK answer
            if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags & TCPHDR_SYN) != 0 &&
                (pkt->flags | (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK) &&
                pkt->ackN == ct_value->sequence) {
                ct_value->state = SYN_RECV;
                ct_value->ttl = timestamp + TCP_SYN_RECV;
                ct_value->sequence = pkt->seqN + HEX_BE_ONE;

                bpf_log_debug("[REV_DIRECTION] Changing "
                              "state from "
                              "SYN_SENT to SYN_RECV\n");

                return PASS_ACTION;
            }
        }
        // Receiving packets outside the 3-Way handshake without
        // completing the handshake
        pkt->connStatus = INVALID;
        bpf_log_debug("[FW/RV_DIRECTION] Failed ACK "
                      "check in "
                      "SYN_SENT state. Flags: %x\n",
                      pkt->flags);
        return PASS_ACTION;
    } else if (ct_value->state == SYN_RECV) {
        if (!reverse) {
            // Expecting an ACK here
            if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags | TCPHDR_ACK) == TCPHDR_ACK &&
                (pkt->ackN == ct_value->sequence)) {
                // Valid ACK to the SYN, ACK
                ct_value->state = ESTABLISHED;
                ct_value->ttl = timestamp + TCP_ESTABLISHED;
                bpf_log_debug("[FW_DIRECTION] Changing "
                              "state from "
                              "SYN_RECV to ESTABLISHED\n");

                return PASS_ACTION;
            }
        } else {
            // The only acceptable packet in SYN_RECV here is a SYN,ACK
            // retransmission
            if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags & TCPHDR_SYN) != 0 &&
                (pkt->flags | (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK) &&
                pkt->ackN == ct_value->sequence) {
                ct_value->ttl = timestamp + TCP_SYN_RECV;

                return PASS_ACTION;
            }
        }
        // Validation failed, either ACK is not the only flag set or
        // the ack number is wrong
        pkt->connStatus = INVALID;
        bpf_log_debug("[FW/RV_DIRECTION] Failed ACK "
                      "check in "
                      "SYN_RECV state. Flags: %x\n",
                      pkt->flags);
        return PASS_ACTION;
    } else if (ct_value->state == ESTABLISHED) {
        bpf_log_debug("Connnection is ESTABLISHED\n");
        if ((pkt->flags & TCPHDR_FIN) != 0) {
            // Received first FIN from "original" direction.
            // Changing state to FIN_WAIT_1
            ct_value->state = FIN_WAIT_1;
            ct_value->ttl = timestamp + TCP_FIN_WAIT;
            ct_value->sequence = pkt->ackN;

            bpf_log_debug("[FW/RV_DIRECTION] Changing "
                          "state from "
                          "ESTABLISHED to FIN_WAIT_1. Seq: %u\n",
                          ct_value->sequence);

            return PASS_ACTION;
        } else {
            ct_value->ttl = timestamp + TCP_ESTABLISHED;
            return PASS_ACTION;
        }
    }
    
    if (ct_value->state == FIN_WAIT_1) {
        bpf_log_debug("Current state is FIN_WAIT_1\n");
        bpf_log_debug("Reverse: %d\n", reverse);
        if (reverse) {
            // Received FIN, waiting for ack on the other side
            if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->seqN == ct_value->sequence)) {
                // Received ACK
                ct_value->state = FIN_WAIT_2;
                ct_value->ttl = timestamp + TCP_FIN_WAIT;

                bpf_log_debug("[FW/RV_DIRECTION] Changing "
                            "state from "
                            "FIN_WAIT_1 to FIN_WAIT_2\n");

            } else {
                // Validation failed, either ACK is not the only flag set or
                // the ack number is wrong
                pkt->connStatus = INVALID;

                bpf_log_debug("[FW/RV_DIRECTION] Failed ACK "
                            "check in "
                            "FIN_WAIT_1 state. Flags: %x. AckSeq: %u\n",
                            pkt->flags, pkt->ackN);
                return PASS_ACTION;
            }
        }
    } 
    
    if (ct_value->state == FIN_WAIT_2) {
        if (reverse) {
            // Already received and acked FIN in this direction, waiting the
            // FIN from the other side
            if ((pkt->flags & TCPHDR_FIN) != 0) {
                // FIN received. Let's wait for it to be acknowledged.
                ct_value->state = LAST_ACK;
                ct_value->ttl = timestamp + TCP_LAST_ACK;
                ct_value->sequence = pkt->ackN;

                bpf_log_debug("[FW/RV_DIRECTION] Changing "
                            "state from "
                            "FIN_WAIT_2 to LAST_ACK\n");

                return PASS_ACTION;
            } else {
                // Still receiving packets
                ct_value->ttl = timestamp + TCP_FIN_WAIT;

                bpf_log_debug("[FW/RV_DIRECTION] Failed FIN "
                            "check in "
                            "FIN_WAIT_2 state. Flags: %x. Seq: %u\n",
                            pkt->flags, ct_value->sequence);

                return PASS_ACTION;
            }
        }
    } 
    
    if (ct_value->state == LAST_ACK) {
        if ((pkt->flags & TCPHDR_ACK && pkt->seqN == ct_value->sequence) != 0) {
            // Ack to the last FIN.
            ct_value->state = TIME_WAIT;
            ct_value->ttl = timestamp + TCP_LAST_ACK;

            bpf_log_debug("[FW/RV_DIRECTION] Changing "
                          "state from "
                          "LAST_ACK to TIME_WAIT\n");
            return PASS_ACTION;
        }
        // Still receiving packets
        ct_value->ttl = timestamp + TCP_LAST_ACK;

        return PASS_ACTION;
    } 
    
    if (ct_value->state == TIME_WAIT) {
        if (pkt->connStatus == NEW) {
            return TCP_NEW;
        } else {
            // Let the packet go, but do not update timers.
            return PASS_ACTION;
        }
    }
    bpf_log_debug("[FW/RV_DIRECTION] Should not get here. "
                  "Flags: %x. State: %d. \n",
                  pkt->flags, ct_value->state);
    return PASS_ACTION;
}

static __always_inline int
advance_tcp_state_machine_full(struct cuckoo_connections_cuckoo_hash_map *cuckoo_map,
                               struct packetHeaders *pkt, uint8_t *ipRev, uint8_t *portRev) {
    struct ct_v *value;
    struct ct_v newEntry = {0};
    struct ct_k key = {0};
    bool reverse = false;

    conntrack_get_key(&key, pkt, ipRev, portRev);
    bpf_log_debug("Key is: %u %u %u %u %u\n", key.srcIp, key.dstIp, key.srcPort, key.dstPort,
                  key.l4proto);
    bpf_log_debug("IPRev: %u. PortRev: %u\n", *ipRev, *portRev);
    /* == TCP  == */
    if (pkt->l4proto == IPPROTO_TCP) {
        // If it is a RST, label it as established.
        if ((pkt->flags & TCPHDR_RST) != 0) {
            // cuckoo_connections_cuckoo_delete(cuckoo_map, &key);
            // connections.delete(&key);
            return PASS_ACTION;
        }
        bpf_log_debug("Checking value in the map\n");
        value = cuckoo_connections_cuckoo_lookup(cuckoo_map, &key);
        // value = bpf_map_lookup_elem(&connections, &key);
        if (value != NULL) {
            bpf_log_debug("Value found in the map\n");
            return_action_t action;
            if ((value->ipRev == *ipRev) && (value->portRev == *portRev)) {
                reverse = false;
            } else if ((value->ipRev != *ipRev) && (value->portRev != *portRev)) {
                reverse = true;
            } else {
                bpf_log_debug("ERROR: IPRev and PortRev are not "
                              "consistent. IPRev: %d. PortRev: %d\n",
                              *ipRev, *portRev);
                goto TCP_MISS;
            }
            action = handle_tcp_conntrack(pkt, value, pkt->timestamp, reverse);
            if (action == TCP_NEW) {
                bpf_log_debug("TCP_NEW\n");
                goto TCP_MISS;
            } else if (action == PASS_ACTION && value->state == TIME_WAIT) {
                bpf_log_debug("Remove connection from the map\n");
                cuckoo_connections_cuckoo_delete(cuckoo_map, &key);
                return PASS_ACTION;
            } else {
                return PASS_ACTION;
            }
        }

        bpf_log_debug("Value not found in the map\n");

    TCP_MISS:;
        // New entry. It has to be a SYN.
        if ((pkt->flags & TCPHDR_SYN) != 0 && (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
            newEntry.state = SYN_SENT;
            newEntry.ttl = pkt->timestamp + TCP_SYN_SENT;
            newEntry.sequence = pkt->seqN + HEX_BE_ONE;

            newEntry.ipRev = *ipRev;
            newEntry.portRev = *portRev;

            bpf_log_debug("New TCP connection. Seq: %u. "
                          "Ack: %u. Flags: %x\n",
                          pkt->seqN, pkt->ackN, pkt->flags);
            bpf_log_debug("Current state is SYN_SENT\n");
            cuckoo_connections_cuckoo_insert(cuckoo_map, &key, &newEntry);
            // bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
            return PASS_ACTION;
        } else {
            // Validation failed
            bpf_log_debug("Validation failed %d\n", pkt->flags);
            return -2;
        }
    }

    // Not TCP packet
    return -1;
}

static __always_inline int
advance_tcp_state_machine_local(struct cuckoo_connections_cuckoo_hash_map *cuckoo_map, struct ct_k *key, struct packetHeaders *pkt, uint8_t *ipRev,
                                uint8_t *portRev, struct ct_v *value, uint32_t curr_value_set) {
    bool reverse = false;

    bpf_log_debug("Key is: %u %u %u %u %u\n", key->srcIp, key->dstIp, key->srcPort, key->dstPort,
                  key->l4proto);
    bpf_log_debug("IPRev: %u. PortRev: %u\n", *ipRev, *portRev);
    /* == TCP  == */
    if (pkt->l4proto == IPPROTO_TCP) {
        // If it is a RST, label it as established.
        if ((pkt->flags & TCPHDR_RST) != 0) {
            // connections.delete(&key);
            return PASS_ACTION;
        }
        if (value != NULL && curr_value_set) {
            bpf_log_debug("advance_tcp_state_machine_local: Value found in the map\n");
            return_action_t action;
            if ((value->ipRev == *ipRev) && (value->portRev == *portRev)) {
                reverse = false;
            } else if ((value->ipRev != *ipRev) && (value->portRev != *portRev)) {
                reverse = true;
            } else {
                bpf_log_debug("Reverse check failed. Goto TCP_MISS\n");
                goto TCP_MISS;
            }

            bpf_log_debug("Running conntrack, reverse: %u\n", reverse);
            action = handle_tcp_conntrack(pkt, value, pkt->timestamp, reverse);
            if (action == TCP_NEW) {
                bpf_log_debug("TCP_NEW. Goto TCP_MISS\n");
                goto TCP_MISS;
            } else if (action == PASS_ACTION && value->state == TIME_WAIT) {
                bpf_log_debug("Remove connection from the map\n");
                cuckoo_connections_cuckoo_delete(cuckoo_map, key);
                // *curr_value_set = false;
                return PASS_ACTION_DEL_VALUE;
            } else {
                return PASS_ACTION;
            }
        }

    TCP_MISS:;
        // New entry. It has to be a SYN.
        if ((pkt->flags & TCPHDR_SYN) != 0 && (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
            value->state = SYN_SENT;
            value->ttl = pkt->timestamp + TCP_SYN_SENT;
            value->sequence = pkt->seqN + HEX_BE_ONE;

            bpf_log_debug("New sequence number is: %u\n", value->sequence);

            value->ipRev = *ipRev;
            value->portRev = *portRev;

            // bpf_map_update_elem(&connections, key, &newEntry, BPF_ANY);
            bpf_log_debug("New connection, setting local variable\n");
            // *curr_value_set = true;
            return TCP_NEW;
        } else {
            // Validation failed
            bpf_log_debug("Validation failed %d\n", pkt->flags);
            return -2;
        }
    }

    // Not TCP packet
    bpf_log_err("Error, received not TCP packet\n");
    return -1;
}

#define PASS_ACTION_FINAL_CTX 1
#define DROP_CTX 2

static int metadata_processing_loop(uint32_t index, void *data) {
    struct metadata_processing_loop_ctx *ctx = (struct metadata_processing_loop_ctx *)data;
    int ret;

    uint32_t *value_set;
    uint32_t value_set_key = 0;
    value_set = bpf_map_lookup_elem(&metadata_loop, &value_set_key);
    if (value_set == NULL) {
        bpf_log_debug("Value set not found in the map\n");
        return 1;
    }

    if (index == (conntrack_cfg.num_pkts - 1)) {
        bpf_log_debug("Dealing with pkt: %i taken from current packet info.\n", index);
        if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 16, 0)) {
            ctx->curr_pkt.timestamp = bpf_ktime_get_boot_ns();
        } else {
            ctx->curr_pkt.timestamp = bpf_ktime_get_ns();
        }

        // value_set = ctx->curr_value_set;
        // // __bpf_memcpy_builtin(&value_set, &ctx->curr_value_set, sizeof(value_set));
        // bpf_log_debug("New value_set: %d", value_set);
        // if (value_set == 1) {
        //     bpf_log_debug("Value set, running local algorithm\n");
        // } else {
        //     bpf_log_debug("Value not set, running full algorithm\n");
        // }
        // bpf_log_debug("New curr_value_set: %d", ctx->curr_value_set);

        if (*value_set == 0) {
            bpf_log_debug("Value not set, running full algorithm\n");
            // We have not seen this connection before
            ret = advance_tcp_state_machine_full(ctx->cuckoo_map, &ctx->curr_pkt, &ctx->curr_ipRev,
                                                 &ctx->curr_portRev);
            if (ret < 0) {
                bpf_log_err("Error in advance_tcp_state_machine_full, ret: %d", ret);
            }
        } else {
            bpf_log_debug("Current value state: %u", ctx->curr_value.state);
            bpf_log_debug("Current value ipRev: %u", ctx->curr_value.ipRev);
            bpf_log_debug("Current value portRev: %u", ctx->curr_value.portRev);
            bpf_log_debug("Current value sequence: %u", ctx->curr_value.sequence);
            bpf_log_debug("Current value ttl: %u", ctx->curr_value.ttl);

            ret = advance_tcp_state_machine_local(ctx->cuckoo_map, &ctx->curr_pkt_key, &ctx->curr_pkt,
                                                  &ctx->curr_ipRev, &ctx->curr_portRev,
                                                  &ctx->curr_value, *value_set);
            if (ret < 0) {
                bpf_log_err("Error in advance_tcp_state_machine_local, ret: %d", ret);
                ctx->ret_code = PASS_ACTION_FINAL_CTX;
                return 1;
            }

            if (ret == TCP_NEW) {
                *value_set = 1;
            } else if (ret == PASS_ACTION_DEL_VALUE) {
                *value_set = 0;
            }

            if (ret == TCP_NEW || ctx->map_curr_value == NULL) {
                bpf_log_debug("Create new entry in the map");
                struct ct_k curr_pkt_key_test;
                __bpf_memcpy_builtin(&curr_pkt_key_test, &ctx->curr_pkt_key, sizeof(struct ct_k));
                cuckoo_connections_cuckoo_insert(ctx->cuckoo_map, &curr_pkt_key_test,
                                                 &ctx->curr_value);
            } else {
                if (ctx->map_curr_value != NULL) {
                    bpf_log_debug("Update existing map entry");
                    ctx->map_curr_value->ipRev = ctx->curr_value.ipRev;
                    ctx->map_curr_value->portRev = ctx->curr_value.portRev;
                    ctx->map_curr_value->sequence = ctx->curr_value.sequence;
                    ctx->map_curr_value->ttl = ctx->curr_value.ttl;
                    ctx->map_curr_value->state = ctx->curr_value.state;
                }
            }
        }
        // This is the last pkt
        ctx->ret_code = PASS_ACTION_FINAL_CTX;
        return 1;
    } else {
        bpf_log_debug("Dealing with pkt: %d taken from the metadata.\n", index);
        struct metadata_elem *md_elem;
        struct packetHeaders pkt = {0};
        md_elem = ctx->data + ctx->nh_off;

        if (ctx->data + ctx->nh_off + sizeof(struct metadata_elem) > ctx->data_end) {
            bpf_log_err("No metadata available in the current pkt\n");
            ctx->ret_code = DROP_CTX;
            return 1;
        }

        pkt.l4proto = md_elem->flow.protocol;
        pkt.srcIp = md_elem->flow.src_ip;
        pkt.dstIp = md_elem->flow.dst_ip;
        pkt.srcPort = md_elem->flow.src_port;
        pkt.dstPort = md_elem->flow.dst_port;

        pkt.ackN = md_elem->info.ackN;
        pkt.seqN = md_elem->info.seqN;
        pkt.flags = md_elem->info.flags;
        pkt.timestamp = md_elem->info.timestamp;

        uint8_t local_ipRev = 0;
        uint8_t local_portRev = 0;
        // This is a trick to ensure the first N packets are skipped
        if (pkt.l4proto == 0) {
            bpf_log_debug("Skip this packet since the info are 0ed\n");
            return 0;
        } else {
            struct ct_k local_key = {0};
            conntrack_get_key(&local_key, &pkt, &local_ipRev, &local_portRev);

            if (local_key.srcIp == ctx->curr_pkt_key.srcIp && local_key.dstIp == ctx->curr_pkt_key.dstIp && 
                local_key.srcPort == ctx->curr_pkt_key.srcPort && local_key.dstPort == ctx->curr_pkt_key.dstPort &&
                local_key.l4proto == ctx->curr_pkt_key.l4proto) {
                bpf_log_debug("Pkt has same key has current packet, use local variable");
                bpf_log_debug("Curr_value_set: %d", *value_set);
                if (*value_set == 0) {
                    bpf_log_debug("Lookup entry in the map");
                    ctx->map_curr_value =
                        cuckoo_connections_cuckoo_lookup(ctx->cuckoo_map, &local_key);
                    if (ctx->map_curr_value) {
                        bpf_log_debug("Setting map_curr_value");
                        memcpy(&ctx->curr_value, ctx->map_curr_value, sizeof(ctx->curr_value));
                        *value_set = 1;
                    }
                }
                // Keys are equals, we have same connection as current pkt
                ret =
                    advance_tcp_state_machine_local(ctx->cuckoo_map, &local_key, &pkt, &local_ipRev, &local_portRev,
                                                    &ctx->curr_value, *value_set);
                if (ret == TCP_NEW) {
                    *value_set = 1;
                } else if (ret == PASS_ACTION_DEL_VALUE) {
                    *value_set = 0;
                }
                bpf_log_debug("Curr_value_set: %d", *value_set);
                if (ret < 0) {
                    bpf_log_err("Error in advance_tcp_state_machine_local, ret: %d", ret);
                    goto PASS_ACTION;
                }
            } else {
                ret = advance_tcp_state_machine_full(ctx->cuckoo_map, &pkt, &local_ipRev,
                                                     &local_portRev);
                if (ret < 0) {
                    bpf_log_err("Error in advance_tcp_state_machine_full, ret: %d", ret);
                    goto PASS_ACTION;
                }
            }
        }
    }

PASS_ACTION:;
    ctx->nh_off += sizeof(struct metadata_elem);
    return 0;
}

SEC("xdp")
int xdp_conntrack_prog(struct xdp_md *ctx) {
    int rc;
    __u16 nh_off = 0;
    __u16 nh_off_md = 0;
    __u16 h_proto;
    __u32 md_size;
    uint32_t zero = 0;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct metadata_processing_loop_ctx loop_ctx = {0};

    loop_ctx.data = data;
    loop_ctx.data_end = data_end;

    bpf_log_debug("Received packet on interface.\n");

    struct cuckoo_connections_cuckoo_hash_map *cuckoo_map =
        bpf_map_lookup_elem(&cuckoo_connections, &zero);
    if (!cuckoo_map) {
        bpf_printk("cuckoo map not found");
        goto DROP;
    }

    loop_ctx.cuckoo_map = cuckoo_map;

    /* Given the new way we are formatting the packet,
     * we can skip the parsing at the beginning.
     *
     * We just need to do some bound checking
     * for Ethernet, then we will have the metadata
     */

    if (!conntrack_cfg.enable_flow_affinity) {
        if (!validate_ethertype(data, data_end, &h_proto, &nh_off)) {
            bpf_log_err("Invalid ethertype\n");
            goto DROP;
        }

        if (h_proto != bpf_htons(ETH_P_IP)) {
            bpf_log_err("Ethernet protocol on the fake Ethernet header is not IPv4\n");
            goto DROP;
        }

        bpf_log_debug("Packet parsed, now starting the conntrack.\n");
    } else {
        bpf_log_debug("Flow Affinity ENABLED, skipping parsing of fake header\n");
    }

    md_size = (conntrack_cfg.num_pkts - 1) * sizeof(struct metadata_elem);
    if (data + nh_off + md_size > data_end) {
        bpf_log_err("No metadata available in the current pkt\n");
        goto DROP;
    }
    nh_off_md = nh_off;
    nh_off += md_size;
    bpf_log_debug("nh_off: %d\n", nh_off);
    rc = parse_packet(data, data_end, &loop_ctx.curr_pkt, &nh_off);

    if (rc < 0) {
        bpf_log_err("Error parsing current packet\n");
        goto DROP;
    }

    conntrack_get_key(&loop_ctx.curr_pkt_key, &loop_ctx.curr_pkt, &loop_ctx.curr_ipRev,
                      &loop_ctx.curr_portRev);

    uint32_t value_set_key = 0;
    uint32_t *value_set = bpf_map_lookup_elem(&metadata_loop, &value_set_key);
    if (value_set == NULL) {
        bpf_log_debug("Value set not found in the map\n");
        return 1;
    }
    *value_set = 0;

    loop_ctx.nh_off = nh_off_md;
    bpf_loop(conntrack_cfg.num_pkts, &metadata_processing_loop, &loop_ctx, 0);

    if (loop_ctx.ret_code == DROP_CTX) {
        goto DROP;
    }

PASS_ACTION_FINAL:;
    if (conntrack_cfg.quiet == 0) {
        struct pkt_md *md;
        __u32 md_key = 0;
        md = bpf_map_lookup_elem(&metadata, &md_key);
        if (md == NULL) {
            bpf_log_err("No elements found in metadata map\n");
            goto DROP;
        }

        uint16_t pkt_len = (uint16_t)(data_end - data);

        NO_TEAR_INC(md->cnt);
        NO_TEAR_ADD(md->bytes_cnt, pkt_len);
    }

    if (conntrack_cfg.redirect_same_iface) {
        bpf_log_debug("Redirect on the same interface\n");
        goto REDIR_SAME_IFACE;
    }

    if (conntrack_cfg.if_index_if2 == 0) {
        bpf_log_err("Redirection is disabled\n");
        goto DROP;
    }

    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    if (data + ETH_HLEN > data_end) {
        bpf_log_err("Packet after modification is invalid! DROP\n");
        goto DROP;
    }

    struct ethhdr *eth = (struct ethhdr *)data;
    eth->h_proto = bpf_htons(ETH_P_IP);

    memcpy(eth->h_source, (void *)conntrack_mac_cfg.if2_src_mac, sizeof(eth->h_source));
    memcpy(eth->h_dest, (void *)conntrack_mac_cfg.if2_dst_mac, sizeof(eth->h_dest));
    bpf_log_debug("Redirect pkt to IF2 iface with ifindex: %d\n", conntrack_cfg.if_index_if2);

    return bpf_redirect(conntrack_cfg.if_index_if2, 0);

REDIR_SAME_IFACE:;
    swap_src_dst_mac(data);
    return XDP_TX;

DROP:;
    bpf_log_debug("Dropping packet!\n");
    return XDP_DROP;
}

/* Redirect require an XDP bpf_prog loaded on the TX device */
SEC("xdp")
int xdp_redirect_dummy_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
