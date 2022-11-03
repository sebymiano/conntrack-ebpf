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

void nbo_uint_to_mac_string(uint64_t mac, char mac_str[32]) {
    uint8_t a[6];
    for (int i = 0; i < 6; i++) {
        a[i] = (mac >> i * 8) & 0xFF;
    }

    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5]);
}

int mac_str_to_byte_array(unsigned char out[6], char *in) {
    unsigned char bytes[6];
    printf("Input string is: %s\n", in);
    if (sscanf(in, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bytes[0], &bytes[1], &bytes[2], &bytes[3],
               &bytes[4], &bytes[5]) != 6) {
        printf("%s is an invalid MAC address", in);
        return -1;
    }
    memcpy(out, bytes, 6);
    return 0;
}

int get_mac_from_iface_name(const char *iface, unsigned char mac_str[6]) {
    struct ifreq ifr;
    int fd, rv;

    strcpy(ifr.ifr_name, iface);
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0) {
        printf("get_iface_mac error opening socket: %s\n", strerror(errno));
        return -1;
    }

    rv = ioctl(fd, SIOCGIFHWADDR, &ifr);
    if (rv >= 0)
        memcpy(mac_str, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
    else {
        close(fd);
        if (errno == NLE_NOADDR || errno == NLE_NODEV) {
            // Device has been deleted
            return -2;
        }

        printf("get_iface_mac error determining the MAC address: %s\n", strerror(errno));
    }
    close(fd);

    // uint64_t mac_;
    // memcpy(&mac_, mac_str, sizeof(mac_));
    // nbo_uint_to_mac_string(mac_, mac_str);
    return 0;
}

int set_iface_up(const char *ifname) {
    struct ifreq ifr;
    int sockfd, rv;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("get_iface_mac error opening socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    ifr.ifr_flags |= IFF_UP;
    rv = ioctl(sockfd, SIOCSIFFLAGS, &ifr);

    return rv;
}

#endif // CONNTRACK_IF_HELPERS_H_