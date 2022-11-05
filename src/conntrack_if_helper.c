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
#include <unistd.h>

#include "conntrack_if_helper.h"
#include "log.h"

void nbo_uint_to_mac_string(uint64_t mac, char mac_str[32]) {
    uint8_t a[6];
    for (int i = 0; i < 6; i++) {
        a[i] = (mac >> i * 8) & 0xFF;
    }

    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5]);
}

int mac_str_to_byte_array(unsigned char out[6], const char *in) {
    unsigned char bytes[6];
    if (sscanf(in, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bytes[0], &bytes[1], &bytes[2], &bytes[3],
               &bytes[4], &bytes[5]) != 6) {
        log_error("%s is an invalid MAC address", in);
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
        log_error("get_iface_mac error opening socket: %s\n", strerror(errno));
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

        log_error("get_iface_mac error determining the MAC address: %s\n", strerror(errno));
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
        log_error("get_iface_mac error opening socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    ifr.ifr_flags |= IFF_UP;
    rv = ioctl(sockfd, SIOCSIFFLAGS, &ifr);

    return rv;
}

int enable_promisc(const char *ifname) {
    struct ifreq ifr;
    int sockfd, rv;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_error("enable_promisc error opening socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    ioctl(sockfd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    
    rv = ioctl(sockfd, SIOCSIFFLAGS, &ifr); 
    return rv;
}

int gen_random_mac(unsigned char out[6]) {
    static const char chars[] = {'0','1','2','3','4','5','6','7',
                                 '8','9','A','B','C','D','E','F'};

    char results[18];

    srand(time(NULL));   // Initialization, should only be called once.
    int i;
    for (i = 0; i < sizeof(results)/sizeof(char); i++) {
        if (i == 2 || i == 5 || i == 8 || i == 11 || i == 14) {
            results[i] = ':';
        } else if (i == 17) {
            results[i] = '\0';
        } else {
            results[i] = chars[rand() % sizeof(chars)];
        }
    }

    log_trace("Generated random MAC: %s", results);

    if (sscanf(results, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &out[0], &out[1], &out[2], &out[3],
               &out[4], &out[5]) != 6) {
        log_error("%s is an invalid MAC address", results);
        return -1;
    }
    
    return 0;
}