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

#ifndef __CONNTRACK_STRUCTS_H
#define __CONNTRACK_STRUCTS_H

#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>

#include "conntrack_common.h"

typedef enum {
    NEW,
    ESTABLISHED,
    RELATED,
    INVALID,
    SYN_SENT,
    SYN_RECV,
    FIN_WAIT_1,
    FIN_WAIT_2,
    LAST_ACK,
    TIME_WAIT
} conntrack_states_t;

struct packetHeaders {
    uint32_t srcIp;
    uint32_t dstIp;
    uint8_t l4proto;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t flags;
    uint32_t seqN;
    uint32_t ackN;
    uint8_t connStatus;
    uint64_t timestamp;
} __attribute__((packed));

struct ct_k {
    uint32_t srcIp;
    uint32_t dstIp;
    uint8_t l4proto;
    uint16_t srcPort;
    uint16_t dstPort;
} __attribute__((packed));

struct pkt_md {
    uint64_t cnt;
    uint64_t bytes_cnt;
} __attribute__((packed));

struct icmphdr {
    u_int8_t type; /* message type */
    u_int8_t code; /* type sub-code */
    u_int16_t checksum;
    union {
        struct {
            u_int16_t id;
            u_int16_t sequence;
        } echo;            /* echo datagram */
        u_int32_t gateway; /* gateway address */
        struct {
            u_int16_t __unused;
            u_int16_t mtu;
        } frag; /* path mtu discovery */
    } un;
};

/*The struct defined in tcp.h lets flags be accessed only one by one,
 *it is not needed here.*/
struct tcp_hdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8 res1 : 4, doff : 4;
    __u8 flags;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));

struct _vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#endif // of __CONNTRACK_STRUCTS_H