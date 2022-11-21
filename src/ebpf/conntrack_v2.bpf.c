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

SEC("xdp")
int xdp_conntrack_prog(struct xdp_md *ctx) {
    int rc;
    struct packetHeaders pkt;
    struct packetHeaders curr_pkt;
    __u16 nh_off;
    __u32 md_size;
    struct metadata_elem *md_elem;

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
    struct ct_k key;
    uint8_t ipRev = 0;
    uint8_t portRev = 0;
    int ret;
    for (int i = 0; i < conntrack_cfg.num_pkts; i++) {
        uint64_t timestamp;
        if (i == (conntrack_cfg.num_pkts - 1)) {
            ipRev = 0;
            portRev = 0;
            if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 16, 0)) {
                timestamp = bpf_ktime_get_boot_ns();
            } else {
                timestamp = bpf_ktime_get_ns();
            }
            bpf_log_debug("Dealing with pkt: %i taken from current packet info.\n", i);
            ret = advance_tcp_state_machine(&key, &curr_pkt, &ipRev, &portRev, timestamp);
            if (ret < 0) {
                bpf_log_err("Received not TCP packet (id: %d)", i);
                goto DROP;
            }
            // This is the last pkt
            goto PASS_ACTION_FINAL;
        } else {
            md_elem = data + nh_off;

            pkt.l4proto = md_elem->flow.protocol;
            pkt.srcIp = md_elem->flow.src_ip;
            pkt.dstIp = md_elem->flow.dst_ip;
            pkt.srcPort = md_elem->flow.src_port;
            pkt.dstPort = md_elem->flow.dst_port;

            pkt.ackN = md_elem->info.ackN;
            pkt.seqN = md_elem->info.seqN;
            pkt.flags = md_elem->info.flags;
            timestamp = md_elem->info.timestamp;

            ipRev = 0;
            portRev = 0;
            // This is a trick to ensure the first N packets are skipped
            if (pkt.l4proto == 0) {
                bpf_log_debug("Skip this packet (id: %d) since the info are 0ed\n", i);
                goto PASS_ACTION;
            } else {
                bpf_log_debug("Dealing with pkt: %i taken from the metadata.\n", i);
                ret = advance_tcp_state_machine(&key, &pkt, &ipRev, &portRev, timestamp);
                if (ret < 0) {
                    bpf_log_err("Received not TCP packet (id: %d)", i);
                    goto DROP;
                }
                goto PASS_ACTION;
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

    if (pkt.connStatus == INVALID) {
        bpf_log_err("Connection status is invalid\n");
    }

    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    if (data + ETH_HLEN > data_end) {
        bpf_log_err("Packet after modification is invalid! DROP\n");
        goto DROP;
    }

    struct ethhdr *eth = (struct ethhdr *)data;
    eth->h_proto = bpf_htons(ETH_P_IP);

    __builtin_memcpy(eth->h_source, (void *)conntrack_mac_cfg.if2_src_mac, sizeof(eth->h_source));
    __builtin_memcpy(eth->h_dest, (void *)conntrack_mac_cfg.if2_dst_mac, sizeof(eth->h_dest));
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
