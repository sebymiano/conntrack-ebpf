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

int my_pid = 0;

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

    for (int i = 0; i < conntrack_cfg.num_pkts; i++) {
        uint64_t timestamp;
        if (i == (conntrack_cfg.num_pkts - 1)) {
            pkt.l4proto = curr_pkt.l4proto;
            pkt.srcIp = curr_pkt.srcIp;
            pkt.dstIp = curr_pkt.dstIp;
            pkt.srcPort = curr_pkt.srcPort;
            pkt.dstPort = curr_pkt.dstPort;

            pkt.ackN = curr_pkt.ackN;
            pkt.seqN = curr_pkt.seqN;
            pkt.flags = curr_pkt.flags;

            timestamp = bpf_ktime_get_boot_ns();
            // timestamp = bpf_ktime_get_ns();
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

            // This is a trick to ensure the first N packets are skipped
            if (pkt.l4proto == 0) goto PASS_ACTION;
        }

        bpf_log_debug("Dealing with pkt: %i taken from the metadata.\n", i);

        struct ct_k key;
        __builtin_memset(&key, 0, sizeof(key));
        uint8_t ipRev = 0;
        uint8_t portRev = 0;

        if (pkt.srcIp <= pkt.dstIp) {
            key.srcIp = pkt.srcIp;
            key.dstIp = pkt.dstIp;
            ipRev = 0;
        } else {
            key.srcIp = pkt.dstIp;
            key.dstIp = pkt.srcIp;
            ipRev = 1;
        }

        key.l4proto = pkt.l4proto;

        if (pkt.srcPort < pkt.dstPort) {
            key.srcPort = pkt.srcPort;
            key.dstPort = pkt.dstPort;
            portRev = 0;
        } else if (pkt.srcPort > pkt.dstPort) {
            key.srcPort = pkt.dstPort;
            key.dstPort = pkt.srcPort;
            portRev = 1;
        } else {
            key.srcPort = pkt.srcPort;
            key.dstPort = pkt.dstPort;
            portRev = ipRev;
        }

        struct ct_v newEntry;
        __builtin_memset(&newEntry, 0, sizeof(newEntry));
        struct ct_v *value;

        /* == TCP  == */
        if (pkt.l4proto == IPPROTO_TCP) {
            // If it is a RST, label it as established.
            if ((pkt.flags & TCPHDR_RST) != 0) {
                // connections.delete(&key);
                goto PASS_ACTION;
            }
            value = bpf_map_lookup_elem(&connections, &key);
            if (value != NULL) {
                return_action_t action;
                if ((value->ipRev == ipRev) && (value->portRev == portRev)) {
                    goto TCP_FORWARD;
                } else if ((value->ipRev != ipRev) && (value->portRev != portRev)) {
                    goto TCP_REVERSE;
                } else {
                    
                    goto TCP_MISS;
                }

            TCP_FORWARD:;
                action = handle_tcp_conntrack_forward(&pkt, value, timestamp);
                if (action == TCP_NEW) {
                    goto TCP_MISS;
                }
                else {
                    goto PASS_ACTION;
                }
                
            TCP_REVERSE:;
                action = handle_tcp_conntrack_reverse(&pkt, value, timestamp);
                if (action == TCP_NEW) {
                    goto TCP_MISS;
                }
                else {
                    goto PASS_ACTION;
                }
                
            }

        TCP_MISS:;

            // New entry. It has to be a SYN.
            if ((pkt.flags & TCPHDR_SYN) != 0 && (pkt.flags | TCPHDR_SYN) == TCPHDR_SYN) {
                newEntry.state = SYN_SENT;
                newEntry.ttl = timestamp + TCP_SYN_SENT;
                newEntry.sequence = pkt.seqN + HEX_BE_ONE;

                newEntry.ipRev = ipRev;
                newEntry.portRev = portRev;

                bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
                goto PASS_ACTION;
            } else {
                // Validation failed
                bpf_log_debug("Validation failed %d\n", pkt.flags);
                goto PASS_ACTION;
            }
        }

        if (pkt.l4proto == IPPROTO_UDP) {
            value = bpf_map_lookup_elem(&connections, &key);
            if (value != NULL) {
                
                if ((value->ipRev == ipRev) && (value->portRev == portRev)) {
                    goto UDP_FORWARD;
                } else if ((value->ipRev != ipRev) && (value->portRev != portRev)) {
                    goto UDP_REVERSE;
                } else {
                    
                    goto UDP_MISS;
                }

            UDP_FORWARD:;

                // Valid entry
                if (value->state == NEW) {
                    // An entry was already present with the NEW state. This means
                    // that there has been no answer, from the other side.
                    // Connection is still NEW.
                    // For now I am refreshing the TTL, this can lead to an
                    // DoS attack where the attacker prevents the entry from being
                    // deleted by continuosly sending packets.
                    value->ttl = timestamp + UDP_NEW_TIMEOUT;
                    
                    goto PASS_ACTION;
                } else {
                    // value->state == ESTABLISHED
                    value->ttl = timestamp + UDP_ESTABLISHED_TIMEOUT;
                    
                    goto PASS_ACTION;
                }

            UDP_REVERSE:;

                if (value->state == NEW) {
                    // An entry was present in the rev direction with the NEW state.
                    // This means that this is an answer, from the other side.
                    // Connection is now ESTABLISHED.
                    value->ttl = timestamp + UDP_NEW_TIMEOUT;
                    value->state = ESTABLISHED;

                    bpf_log_debug("[REV_DIRECTION] Changing state "
                                "from "
                                "NEW to ESTABLISHED\n");
                    
                    goto PASS_ACTION;
                } else {
                    // value->state == ESTABLISHED
                    value->ttl = timestamp + UDP_ESTABLISHED_TIMEOUT;
                    
                    goto PASS_ACTION;
                }
            }

        UDP_MISS:;

            // No entry found in both directions. Create one.
            newEntry.ttl = timestamp + UDP_NEW_TIMEOUT;
            newEntry.state = NEW;
            newEntry.sequence = 0;

            newEntry.ipRev = ipRev;
            newEntry.portRev = portRev;

            bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
            goto PASS_ACTION;
        }

PASS_ACTION:;
        nh_off += sizeof(struct metadata_elem);
        continue;
    }

PASS_ACTION_FINAL:;

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