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

typedef enum return_action { PASS_ACTION = 0, TCP_NEW } return_action_t;

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

static __always_inline return_action_t handle_tcp_conntrack(struct packetHeaders *pkt,
                                                            struct ct_v *ct_value,
                                                            uint64_t timestamp, bool reverse) {
    if (ct_value->state == SYN_SENT) {
        if (!reverse) {
            // Still haven't received a SYN,ACK To the SYN
            if ((pkt->flags & TCPHDR_SYN) != 0 && (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
                // Another SYN. It is valid, probably a retransmission.
                ct_value->ttl = timestamp + TCP_SYN_SENT;
                return PASS_ACTION;
            }
        } else {
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
    } else if (ct_value->state == FIN_WAIT_1) {
        // Received FIN in reverse direction, waiting for ack from this
        // side
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
    } else if (ct_value->state == FIN_WAIT_2) {
        // Already received and acked FIN in rev direction, waiting the
        // FIN from the this side
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
    } else if (ct_value->state == LAST_ACK) {
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
    } else

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

static __always_inline int advance_tcp_state_machine_full(struct cuckoo_connections_cuckoo_hash_map *cuckoo_map, struct packetHeaders *pkt, uint8_t *ipRev,
                                                          uint8_t *portRev) {
    struct ct_v *value;
    struct ct_v newEntry = {0};
    struct ct_k key = {0};
    bool reverse = false;

    conntrack_get_key(&key, pkt, ipRev, portRev);

    /* == TCP  == */
    if (pkt->l4proto == IPPROTO_TCP) {
        // If it is a RST, label it as established.
        if ((pkt->flags & TCPHDR_RST) != 0) {
            // connections.delete(&key);
            return PASS_ACTION;
        }
        value = cuckoo_connections_cuckoo_lookup(cuckoo_map, &key);
        // value = bpf_map_lookup_elem(&connections, &key);
        if (value != NULL) {
            return_action_t action;
            if ((value->ipRev == *ipRev) && (value->portRev == *portRev)) {
                reverse = false;
            } else if ((value->ipRev != *ipRev) && (value->portRev != *portRev)) {
                reverse = true;
            } else {
                goto TCP_MISS;
            }
            action = handle_tcp_conntrack(pkt, value, pkt->timestamp, reverse);
            if (action == TCP_NEW) {
                goto TCP_MISS;
            } else {
                return PASS_ACTION;
            }
        }

    TCP_MISS:;
        // New entry. It has to be a SYN.
        if ((pkt->flags & TCPHDR_SYN) != 0 && (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
            newEntry.state = SYN_SENT;
            newEntry.ttl = pkt->timestamp + TCP_SYN_SENT;
            newEntry.sequence = pkt->seqN + HEX_BE_ONE;

            newEntry.ipRev = *ipRev;
            newEntry.portRev = *portRev;

            cuckoo_connections_cuckoo_insert(cuckoo_map, &key, &newEntry);
            // bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
            return PASS_ACTION;
        } else {
            // Validation failed
            bpf_log_debug("Validation failed %d\n", pkt->flags);
            return -1;
        }
    }

    // Not TCP packet
    return -1;
}

static __always_inline int
advance_tcp_state_machine_local(struct ct_k *key, struct packetHeaders *pkt, uint8_t *ipRev,
                                uint8_t *portRev, struct ct_v *value, bool *curr_value_set) {
    bool reverse = false;
    /* == TCP  == */
    if (pkt->l4proto == IPPROTO_TCP) {
        // If it is a RST, label it as established.
        if ((pkt->flags & TCPHDR_RST) != 0) {
            // connections.delete(&key);
            return PASS_ACTION;
        }
        if (value != NULL && *curr_value_set) {
            return_action_t action;
            if ((value->ipRev == *ipRev) && (value->portRev == *portRev)) {
                reverse = false;
            } else if ((value->ipRev != *ipRev) && (value->portRev != *portRev)) {
                reverse = true;
            } else {
                goto TCP_MISS;
            }

            action = handle_tcp_conntrack(pkt, value, pkt->timestamp, reverse);
            if (action == TCP_NEW) {
                goto TCP_MISS;
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

            value->ipRev = *ipRev;
            value->portRev = *portRev;

            // bpf_map_update_elem(&connections, key, &newEntry, BPF_ANY);
            bpf_log_debug("New connection, setting local variable\n");
            *curr_value_set = true;
            return TCP_NEW;
        } else {
            // Validation failed
            bpf_log_debug("Validation failed %d\n", pkt->flags);
            return -1;
        }
    }

    // Not TCP packet
    bpf_log_err("Error, received not TCP packet\n");
    return -1;
}

SEC("xdp")
int xdp_conntrack_prog(struct xdp_md *ctx) {
    int rc;
    struct packetHeaders curr_pkt = {0};
    __u16 nh_off = 0;
    __u16 h_proto;
    __u32 md_size;
    uint32_t zero = 0;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_log_debug("Received packet on interface.\n");

    struct cuckoo_connections_cuckoo_hash_map *cuckoo_map = bpf_map_lookup_elem(&cuckoo_connections, &zero);
    if (!cuckoo_map) {
        bpf_printk("cuckoo map not found");
        goto DROP;
    }

    /* Given the new way we are formatting the packet, 
     * we can skip the parsing at the beginning.
     *
     * We just need to do some bound checking
     * for Ethernet, then we will have the metadata
     */

    if (!validate_ethertype(data, data_end, &h_proto, &nh_off)) {
        bpf_log_err("Invalid ethertype\n");
        goto DROP;
    }

    if (h_proto != bpf_htons(ETH_P_IP)) {
        bpf_log_err("Ethernet protocol on the fake Ethernet header is not IPv4\n");
        goto DROP;
    }

    bpf_log_debug("Packet parsed, now starting the conntrack.\n");

    md_size = (conntrack_cfg.num_pkts - 1) * sizeof(struct metadata_elem);
    if (data + nh_off + md_size > data_end) {
        bpf_log_err("No metadata available in the current pkt\n");
        goto DROP;
    }

    nh_off += md_size;

    rc = parse_packet(data, data_end, &curr_pkt, &nh_off);

    if (rc < 0) {
        bpf_log_err("Error parsing current packet\n");
        goto DROP;
    }

    struct ct_k curr_pkt_key = {0};

    uint8_t curr_ipRev = 0;
    uint8_t curr_portRev = 0;

    conntrack_get_key(&curr_pkt_key, &curr_pkt, &curr_ipRev, &curr_portRev);
    struct ct_v curr_value = {0};

    bool curr_value_set = false;
    struct ct_v *map_curr_value = NULL;

    int ret;
    for (int i = 0; i < conntrack_cfg.num_pkts; i++) {
        if (i == (conntrack_cfg.num_pkts - 1)) {
            bpf_log_debug("Dealing with pkt: %i taken from current packet info.\n", i);
            if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 16, 0)) {
                curr_pkt.timestamp = bpf_ktime_get_boot_ns();
            } else {
                curr_pkt.timestamp = bpf_ktime_get_ns();
            }

            bpf_log_debug("Current value is not NULL, this means other packets in the md had "
                          "same connection as current one");
            // Keys are equals, we have same connection as current pkt
            ret = advance_tcp_state_machine_local(&curr_pkt_key, &curr_pkt, &curr_ipRev,
                                                  &curr_portRev, &curr_value, &curr_value_set);
            if (ret < 0) {
                bpf_log_err("Received not TCP packet (id: %d)", i);
                goto PASS_ACTION_FINAL;
            }

            if (ret == TCP_NEW || map_curr_value == NULL) {
                bpf_log_debug("Create new entry in the map");
                cuckoo_connections_cuckoo_insert(cuckoo_map, &curr_pkt_key, &curr_value);
                // bpf_map_update_elem(&connections, &curr_pkt_key, &curr_value, BPF_ANY);
            } else {
                if (map_curr_value != NULL) {
                    bpf_log_debug("Update existing map entry");
                    map_curr_value->ipRev = curr_value.ipRev;
                    map_curr_value->portRev = curr_value.portRev;
                    map_curr_value->sequence = curr_value.sequence;
                    map_curr_value->ttl = curr_value.ttl;
                    map_curr_value->state = curr_value.state;
                }
            }
            // This is the last pkt
            goto PASS_ACTION_FINAL;
        } else {
            bpf_log_debug("Dealing with pkt: %d taken from the metadata.\n", i);
            struct metadata_elem *md_elem;
            struct packetHeaders pkt = {0};
            md_elem = data + nh_off;

            if (data + nh_off + sizeof(struct metadata_elem) > data_end) {
                bpf_log_err("No metadata available in the current pkt\n");
                goto DROP;
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

                if (memcmp(&local_key, &curr_pkt_key, sizeof(curr_pkt_key)) == 0) {
                    bpf_log_debug("Pkt has same key has current packet, use local variable");
                    if (!curr_value_set) {
                        map_curr_value = cuckoo_connections_cuckoo_lookup(cuckoo_map, &local_key);
                        if (map_curr_value) {
                            memcpy(&curr_value, map_curr_value, sizeof(curr_value));
                            curr_value_set = true;
                        }
                    }
                    // Keys are equals, we have same connection as current pkt
                    ret = advance_tcp_state_machine_local(&local_key, &pkt, &local_ipRev,
                                                          &local_portRev, &curr_value,
                                                          &curr_value_set);
                    if (ret < 0) {
                        bpf_log_err("Received not TCP packet");
                        goto PASS_ACTION;
                    }
                } else {
                    ret = advance_tcp_state_machine_full(cuckoo_map, &pkt, &local_ipRev, &local_portRev);
                    if (ret < 0) {
                        bpf_log_err("Received not TCP packet");
                        goto PASS_ACTION;
                    }
                }
            }
        }

    PASS_ACTION:;
        nh_off += sizeof(struct metadata_elem);
        continue;
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
