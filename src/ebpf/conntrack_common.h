/*
 * Copyright 2022 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CONNTRACK_COMMON_H_
#define CONNTRACK_COMMON_H_

#define IF_INDEX_IF1 1
#define IF_INDEX_IF2 2

#define CONNTRACK_DROP -1

#define FORCE_INLINE inline __attribute__((__always_inline__))

#include <stddef.h>
#include <stdint.h>
#include <linux/types.h>

#define ICMP_ECHOREPLY 0       /* Echo Reply			*/
#define ICMP_ECHO 8            /* Echo Request			*/
#define ICMP_TIMESTAMP 13      /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply		*/
#define ICMP_INFO_REQUEST 15   /* Information Request		*/
#define ICMP_INFO_REPLY 16     /* Information Reply		*/
#define ICMP_ADDRESS 17        /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY 18   /* Address Mask Reply		*/

// ns
#define UDP_ESTABLISHED_TIMEOUT 180000000000
#define UDP_NEW_TIMEOUT 30000000000
#define ICMP_TIMEOUT 30000000000
#define TCP_ESTABLISHED 432000000000000
#define TCP_SYN_SENT 120000000000
#define TCP_SYN_RECV 60000000000
#define TCP_LAST_ACK 30000000000
#define TCP_FIN_WAIT 120000000000
#define TCP_TIME_WAIT 120000000000

#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_ACK 0x10

#define HEX_BE_ONE 0x1000000

const volatile struct {
    __u8 log_level;
    __u32 if_index_if1;
    __u32 if_index_if2;
    __u8 enable_spin_locks;
    __u8 num_pkts;
    __u8 enable_flow_affinity;
    __u8 redirect_same_iface;
    __u8 quiet;
    __u32 queues_rsspp;
} conntrack_cfg = {};

const volatile struct {
    unsigned char if1_src_mac[6];
    unsigned char if1_dst_mac[6];
    unsigned char if2_src_mac[6];
    unsigned char if2_dst_mac[6];
} conntrack_mac_cfg = {};

#define ctr_spin_lock(...) (conntrack_cfg.enable_spin_locks <= 0 ? (0) : bpf_spin_lock(__VA_ARGS__))

#define ctr_spin_unlock(...)                                                                       \
    (conntrack_cfg.enable_spin_locks <= 0 ? (0) : bpf_spin_unlock(__VA_ARGS__))

typedef __u8 __attribute__((__may_alias__)) __u8_alias_t;
typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;

static __always_inline void __read_once_size(const volatile void *p, void *res, int size) {
    switch (size) {
    case 1:
        *(__u8_alias_t *)res = *(volatile __u8_alias_t *)p;
        break;
    case 2:
        *(__u16_alias_t *)res = *(volatile __u16_alias_t *)p;
        break;
    case 4:
        *(__u32_alias_t *)res = *(volatile __u32_alias_t *)p;
        break;
    case 8:
        *(__u64_alias_t *)res = *(volatile __u64_alias_t *)p;
        break;
    default:
        asm volatile("" : : : "memory");
        __builtin_memcpy((void *)res, (const void *)p, size);
        asm volatile("" : : : "memory");
    }
}

static __always_inline void __write_once_size(volatile void *p, void *res, int size) {
    switch (size) {
    case 1:
        *(volatile __u8_alias_t *)p = *(__u8_alias_t *)res;
        break;
    case 2:
        *(volatile __u16_alias_t *)p = *(__u16_alias_t *)res;
        break;
    case 4:
        *(volatile __u32_alias_t *)p = *(__u32_alias_t *)res;
        break;
    case 8:
        *(volatile __u64_alias_t *)p = *(__u64_alias_t *)res;
        break;
    default:
        asm volatile("" : : : "memory");
        __builtin_memcpy((void *)p, (const void *)res, size);
        asm volatile("" : : : "memory");
    }
}

#define READ_ONCE(x)                                                                               \
    ({                                                                                             \
        union {                                                                                    \
            typeof(x) __val;                                                                       \
            char __c[1];                                                                           \
        } __u = {.__c = {0}};                                                                      \
        __read_once_size(&(x), __u.__c, sizeof(x));                                                \
        __u.__val;                                                                                 \
    })

#define WRITE_ONCE(x, val)                                                                         \
    ({                                                                                             \
        union {                                                                                    \
            typeof(x) __val;                                                                       \
            char __c[1];                                                                           \
        } __u = {.__val = (val)};                                                                  \
        __write_once_size(&(x), __u.__c, sizeof(x));                                               \
        __u.__val;                                                                                 \
    })

#define NO_TEAR_ADD(x, val) WRITE_ONCE((x), READ_ONCE(x) + (val))
#define NO_TEAR_INC(x) NO_TEAR_ADD((x), 1)

#endif // CONNTRACK_COMMON_H_