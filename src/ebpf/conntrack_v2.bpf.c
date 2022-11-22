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
#include "conntrack_helpers.h"

extern __u32 LINUX_KERNEL_VERSION __kconfig;

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

static __always_inline int handle_pkt_from_md(void *data, __u16 nh_off,
                                              const struct ct_k *curr_pkt_key,
                                              struct ct_v *curr_value, bool *curr_value_set) {
    struct metadata_elem *md_elem;
    int ret;
    struct packetHeaders pkt = {0};
    md_elem = data + nh_off;

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

        if (memcmp(&local_key, curr_pkt_key, sizeof(*curr_pkt_key)) == 0) {
            struct ct_v *local_curr_value = NULL;
            bpf_log_debug("Pkt has same key has current packet, use local variable");
            if (!(*curr_value_set)) {
                local_curr_value = bpf_map_lookup_elem(&connections, &local_key);
                if (local_curr_value) {
                    memcpy(curr_value, local_curr_value, sizeof(*curr_value));
                    *curr_value_set = true;
                }
            }
            // Keys are equals, we have same connection as current pkt
            ret = advance_tcp_state_machine_local(&local_key, &pkt, &local_ipRev, &local_portRev,
                                                  curr_value, curr_value_set);
            if (ret < 0) {
                bpf_log_err("Received not TCP packet");
                return 0;
            }
        } else {
            ret = advance_tcp_state_machine_full(&pkt, &local_ipRev, &local_portRev);
            if (ret < 0) {
                bpf_log_err("Received not TCP packet");
                return 0;
            }
        }
    }
    return 0;
}

SEC("xdp")
int xdp_conntrack_prog(struct xdp_md *ctx) {
    int rc;
    struct packetHeaders curr_pkt = {0};
    __u16 nh_off;
    __u32 md_size;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_log_debug("Received packet on interface.\n");

    rc = parse_packet(data, data_end, &curr_pkt, &nh_off);

    if (rc < 0)
        goto DROP;

    bpf_log_debug("Packet parsed, now starting the conntrack.\n");

    md_size = (conntrack_cfg.num_pkts - 1) * sizeof(struct metadata_elem);
    if (data + nh_off + md_size > data_end) {
        bpf_log_err("No metadata available in the current pkt\n");
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
                bpf_map_update_elem(&connections, &curr_pkt_key, &curr_value, BPF_ANY);
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
                        map_curr_value = bpf_map_lookup_elem(&connections, &local_key);
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
                    ret = advance_tcp_state_machine_full(&pkt, &local_ipRev, &local_portRev);
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
