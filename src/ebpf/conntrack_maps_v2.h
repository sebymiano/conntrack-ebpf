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

#ifndef __CONNTRACK_MAPS_H
#define __CONNTRACK_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdint.h>

#include "conntrack_structs.h"

#define CONNTRACK_MAP_MAX_SIZE 65536

struct ct_v {
    uint64_t ttl;
    uint8_t state;
    uint8_t ipRev;
    uint8_t portRev;
    uint32_t sequence;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, struct ct_k);
    __type(value, struct ct_v);
    __uint(max_entries, CONNTRACK_MAP_MAX_SIZE);
} connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct pkt_md);
    __uint(max_entries, 1);
} metadata SEC(".maps");

#endif // of __CONNTRACK_MAPS_H