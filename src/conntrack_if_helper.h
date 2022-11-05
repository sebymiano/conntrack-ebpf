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

#ifndef CONNTRACK_IF_HELPERS_H_
#define CONNTRACK_IF_HELPERS_H_

#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc.h>
#include <netlink/socket.h>
#include <errno.h>

void nbo_uint_to_mac_string(uint64_t mac, char mac_str[32]);
int mac_str_to_byte_array(unsigned char out[6], const char *in);
int get_mac_from_iface_name(const char *iface, unsigned char mac_str[6]);
int set_iface_up(const char *ifname);
int enable_promisc(const char *ifname);
int gen_random_mac(unsigned char out[6]);

#endif // CONNTRACK_IF_HELPERS_H_