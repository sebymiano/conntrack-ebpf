/* Copyright (c) 2017 The Polycube Authors
 * Copyright (c) 2022 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __CONNTRACK_PARSER_H
#define __CONNTRACK_PARSER_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
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
#include "conntrack_common.h"
#include "conntrack_bpf_log.h"

static FORCE_INLINE void swap_src_dst_mac(void *data) {
    unsigned short *p = data;
    unsigned short dst[3];

    dst[0] = p[0];
    dst[1] = p[1];
    dst[2] = p[2];
    p[0] = p[3];
    p[1] = p[4];
    p[2] = p[5];
    p[3] = dst[0];
    p[4] = dst[1];
    p[5] = dst[2];
}

static bool validate_ethertype(void *data, void *data_end, __u16 *h_proto, __u16 *nh_off) {
    *nh_off = ETH_HLEN;

    if (data + *nh_off > data_end)
        return false;

    struct ethhdr *eth = (struct ethhdr *)data;
    *h_proto = eth->h_proto;

    if (bpf_ntohs(*h_proto) < ETH_P_802_3_MIN)
        return false; // non-Ethernet II unsupported

// parse double vlans
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (*h_proto == bpf_ntohs(ETH_P_8021Q) || *h_proto == bpf_ntohs(ETH_P_8021AD)) {
            struct _vlan_hdr *vhdr;
            vhdr = (struct _vlan_hdr *)(data + *nh_off);
            *nh_off += sizeof(struct _vlan_hdr);
            if (data + *nh_off > data_end) {
                return false;
            }
            *h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    return true;
}

static int parse_packet(void *data, void *data_end, struct packetHeaders *pkt, __u16 *nh_off) {
    __u16 l3_proto;
    struct iphdr *iph;

    if (!validate_ethertype(data, data_end, &l3_proto, nh_off)) {
        bpf_log_warning("Unrecognized L3 protocol\n");
        goto DROP;
    }

    switch (l3_proto) {
    case bpf_htons(ETH_P_IP):
        goto IP; // ipv4 packet
    case bpf_htons(ETH_P_IPV6):
        goto IP6;
        break;
    case bpf_htons(ETH_P_ARP):
        goto ARP; // arp packet
    default:
        goto DROP;
    }

IP:;
    iph = (struct iphdr *)(data + *nh_off);
    if ((void *)iph + sizeof(*iph) > data_end) {
        bpf_log_err("Invalid IPv4 packet\n");
        goto DROP;
    }

    *nh_off += sizeof(*iph);

    pkt->srcIp = iph->saddr;
    pkt->dstIp = iph->daddr;
    pkt->l4proto = iph->protocol;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcp_hdr *tcp = NULL;
        tcp = (struct tcp_hdr *)(data + sizeof(struct ethhdr) + sizeof(*iph));
        if (data + sizeof(struct ethhdr) + sizeof(*iph) + sizeof(*tcp) > data_end)
            goto DROP;
        *nh_off += sizeof(*tcp);
        pkt->srcPort = tcp->source;
        pkt->dstPort = tcp->dest;
        pkt->seqN = tcp->seq;
        pkt->ackN = tcp->ack_seq;
        pkt->flags = tcp->flags;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = NULL;
        udp = (struct udphdr *)(data + sizeof(struct ethhdr) + sizeof(*iph));
        if (data + sizeof(struct ethhdr) + sizeof(*iph) + sizeof(*udp) > data_end)
            goto DROP;
        *nh_off += sizeof(*udp);
        pkt->srcPort = udp->source;
        pkt->dstPort = udp->dest;
    } else {
        goto DROP;
    }

    return 0;

IP6:;
    bpf_log_debug("Received IPv6 Packet. Dropping\n");
    return CONNTRACK_DROP;

ARP:;
    bpf_log_debug("Received ARP. Dropping\n");
    return CONNTRACK_DROP;

DROP:;
    bpf_log_debug("Dropping packet.\n");
    return CONNTRACK_DROP;
}

#endif // of __CONNTRACK_PARSER_H