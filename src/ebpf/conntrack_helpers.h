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

#ifndef CONNTRACK_HELPERS_H_
#define CONNTRACK_HELPERS_H_

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

#include "cilium_builtin.h"

#include "conntrack_structs.h"
#include "conntrack_common.h"
#include "conntrack_bpf_log.h"

typedef enum return_action { PASS_ACTION = 0, TCP_NEW } return_action_t;

static FORCE_INLINE void conntrack_get_key(struct ct_k *key, const struct packetHeaders *pkt,
                                           uint8_t *ipRev, uint8_t *portRev) {
    if (pkt->srcIp == pkt->dstIp) {
        if (pkt->srcPort <= pkt->dstPort) {
            key->srcPort = pkt->srcPort;
            key->dstPort = pkt->dstPort;
            *portRev = 0;
            *ipRev = 0;
        } else {
            key->srcPort = pkt->dstPort;
            key->dstPort = pkt->srcPort;
            *portRev = 1;
            *ipRev = 1;
        }
    } else if (pkt->srcIp < pkt->dstIp) {
        key->srcIp = pkt->srcIp;
        key->dstIp = pkt->dstIp;
        key->srcPort = pkt->srcPort;
        key->dstPort = pkt->dstPort;
        *ipRev = 0;
        *portRev = 0;
    } else {
        key->srcIp = pkt->dstIp;
        key->dstIp = pkt->srcIp;
        key->srcPort = pkt->dstPort;
        key->dstPort = pkt->srcPort;
        *ipRev = 1;
        *portRev = 1;
    }

    key->l4proto = pkt->l4proto;
}

static FORCE_INLINE return_action_t handle_tcp_conntrack_forward(struct packetHeaders *pkt,
                                                                 struct ct_v *ct_value,
                                                                 uint64_t timestamp) {
    // Found in forward direction
    if (ct_value->state == SYN_SENT) {
        // Still haven't received a SYN,ACK To the SYN
        if ((pkt->flags & TCPHDR_SYN) != 0 && (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
            // Another SYN. It is valid, probably a retransmission.
            ct_value->ttl = timestamp + TCP_SYN_SENT;
            return PASS_ACTION;
        } else {
            // Receiving packets outside the 3-Way handshake without
            // completing the handshake
            pkt->connStatus = INVALID;
            bpf_log_debug("[FW_DIRECTION] Failed ACK "
                          "check in "
                          "SYN_SENT state. Flags: %x\n",
                          pkt->flags);
            return PASS_ACTION;
        }
    }

    if (ct_value->state == SYN_RECV) {
        // Expecting an ACK here
        if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags | TCPHDR_ACK) == TCPHDR_ACK &&
            (pkt->ackN == ct_value->sequence)) {
            // Valid ACK to the SYN, ACK
            ct_value->state = ESTABLISHED;
            ct_value->ttl = timestamp + TCP_ESTABLISHED;
            bpf_log_debug("[FW_DIRECTION] Changing "
                          "state from "
                          "SYN_RECV to ESTABLISHED\n");

            return PASS_ACTION;
        } else {
            // Validation failed, either ACK is not the only flag set or
            // the ack number is wrong
            pkt->connStatus = INVALID;

            bpf_log_debug("[FW_DIRECTION] Failed ACK "
                          "check in "
                          "SYN_RECV state. Flags: %x\n",
                          pkt->flags);
            return PASS_ACTION;
        }
    }

    if (ct_value->state == ESTABLISHED) {
        bpf_log_debug("Connnection is ESTABLISHED\n");
        if ((pkt->flags & TCPHDR_FIN) != 0) {
            // Received first FIN from "original" direction.
            // Changing state to FIN_WAIT_1
            ct_value->state = FIN_WAIT_1;
            ct_value->ttl = timestamp + TCP_FIN_WAIT;
            ct_value->sequence = pkt->ackN;

            bpf_log_debug("[FW_DIRECTION] Changing "
                          "state from "
                          "ESTABLISHED to FIN_WAIT_1. Seq: %u\n",
                          ct_value->sequence);

            return PASS_ACTION;
        } else {
            ct_value->ttl = timestamp + TCP_ESTABLISHED;

            return PASS_ACTION;
        }
    }

    if (ct_value->state == FIN_WAIT_1) {
        // Received FIN in reverse direction, waiting for ack from this
        // side
        if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->seqN == ct_value->sequence)) {
            // Received ACK
            ct_value->state = FIN_WAIT_2;
            ct_value->ttl = timestamp + TCP_FIN_WAIT;

            bpf_log_debug("[FW_DIRECTION] Changing "
                          "state from "
                          "FIN_WAIT_1 to FIN_WAIT_2\n");

        } else {
            // Validation failed, either ACK is not the only flag set or
            // the ack number is wrong
            pkt->connStatus = INVALID;

            bpf_log_debug("[FW_DIRECTION] Failed ACK "
                          "check in "
                          "FIN_WAIT_1 state. Flags: %x. AckSeq: %u\n",
                          pkt->flags, pkt->ackN);
            return PASS_ACTION;
        }
    }

    if (ct_value->state == FIN_WAIT_2) {
        // Already received and acked FIN in rev direction, waiting the
        // FIN from the this side
        if ((pkt->flags & TCPHDR_FIN) != 0) {
            // FIN received. Let's wait for it to be acknowledged.
            ct_value->state = LAST_ACK;
            ct_value->ttl = timestamp + TCP_LAST_ACK;
            ct_value->sequence = pkt->ackN;

            bpf_log_debug("[FW_DIRECTION] Changing "
                          "state from "
                          "FIN_WAIT_2 to LAST_ACK\n");

            return PASS_ACTION;
        } else {
            // Still receiving packets
            ct_value->ttl = timestamp + TCP_FIN_WAIT;

            bpf_log_debug("[FW_DIRECTION] Failed FIN "
                          "check in "
                          "FIN_WAIT_2 state. Flags: %x. Seq: %u\n",
                          pkt->flags, ct_value->sequence);

            return PASS_ACTION;
        }
    }

    if (ct_value->state == LAST_ACK) {
        if ((pkt->flags & TCPHDR_ACK && pkt->seqN == ct_value->sequence) != 0) {
            // Ack to the last FIN.
            ct_value->state = TIME_WAIT;
            ct_value->ttl = timestamp + TCP_LAST_ACK;

            bpf_log_debug("[FW_DIRECTION] Changing "
                          "state from "
                          "LAST_ACK to TIME_WAIT\n");
            return PASS_ACTION;
        }
        // Still receiving packets
        ct_value->ttl = timestamp + TCP_LAST_ACK;

        return PASS_ACTION;
    }

    if (ct_value->state == TIME_WAIT) {
        if (pkt->connStatus == NEW) {
            return TCP_NEW;
        } else {
            // Let the packet go, but do not update timers.
            return PASS_ACTION;
        }
    }

    bpf_log_debug("[FW_DIRECTION] Should not get here. "
                  "Flags: %x. State: %d. \n",
                  pkt->flags, ct_value->state);
    return PASS_ACTION;
}

static FORCE_INLINE return_action_t handle_tcp_conntrack_reverse(struct packetHeaders *pkt,
                                                                 struct ct_v *ct_value,
                                                                 uint64_t timestamp) {
    // Found in reverse direction
    if (ct_value->state == SYN_SENT) {
        // This should be a SYN, ACK answer
        if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags & TCPHDR_SYN) != 0 &&
            (pkt->flags | (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK) &&
            pkt->ackN == ct_value->sequence) {
            ct_value->state = SYN_RECV;
            ct_value->ttl = timestamp + TCP_SYN_RECV;
            ct_value->sequence = pkt->seqN + HEX_BE_ONE;

            bpf_log_debug("[REV_DIRECTION] Changing "
                          "state from "
                          "SYN_SENT to SYN_RECV\n");

            return PASS_ACTION;
        }
        // Here is an unexpected packet, only a SYN, ACK is acepted as
        // an answer to a SYN
        pkt->connStatus = INVALID;

        return PASS_ACTION;
    }

    if (ct_value->state == SYN_RECV) {
        // The only acceptable packet in SYN_RECV here is a SYN,ACK
        // retransmission
        if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->flags & TCPHDR_SYN) != 0 &&
            (pkt->flags | (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK) &&
            pkt->ackN == ct_value->sequence) {
            ct_value->ttl = timestamp + TCP_SYN_RECV;

            return PASS_ACTION;
        }
        pkt->connStatus = INVALID;

        return PASS_ACTION;
    }

    if (ct_value->state == ESTABLISHED) {
        bpf_log_debug("Connnection is ESTABLISHED\n");
        if ((pkt->flags & TCPHDR_FIN) != 0) {
            // Initiating closing sequence
            ct_value->state = FIN_WAIT_1;
            ct_value->ttl = timestamp + TCP_FIN_WAIT;
            ct_value->sequence = pkt->ackN;

            bpf_log_debug("[REV_DIRECTION] Changing "
                          "state from "
                          "ESTABLISHED to FIN_WAIT_1. Seq: %x\n",
                          ct_value->sequence);

            return PASS_ACTION;
        } else {
            ct_value->ttl = timestamp + TCP_ESTABLISHED;

            return PASS_ACTION;
        }
    }

    if (ct_value->state == FIN_WAIT_1) {
        // Received FIN in reverse direction, waiting for ack from this
        // side
        if ((pkt->flags & TCPHDR_ACK) != 0 && (pkt->seqN == ct_value->sequence)) {
            // Received ACK
            ct_value->state = FIN_WAIT_2;
            ct_value->ttl = timestamp + TCP_FIN_WAIT;

            bpf_log_debug("[REV_DIRECTION] Changing "
                          "state from "
                          "FIN_WAIT_1 to FIN_WAIT_2\n");

            // Don't forward packet, we can continue performing the
            // check in case the current packet is a ACK,FIN. In this
            // case we match the next if statement
        } else {
            // Validation failed, either ACK is not the only flag set or
            // the ack number is wrong
            pkt->connStatus = INVALID;

            bpf_log_debug("[REV_DIRECTION] Failed ACK "
                          "check in "
                          "FIN_WAIT_1 state. Flags: %d. AckSeq: %d\n",
                          pkt->flags, pkt->ackN);
            return PASS_ACTION;
        }
    }

    if (ct_value->state == FIN_WAIT_2) {
        // Already received and acked FIN in "original" direction,
        // waiting the FIN from this side
        if ((pkt->flags & TCPHDR_FIN) != 0) {
            // FIN received. Let's wait for it to be acknowledged.
            ct_value->state = LAST_ACK;
            ct_value->ttl = timestamp + TCP_LAST_ACK;
            ct_value->sequence = pkt->ackN;

            bpf_log_debug("[REV_DIRECTION] Changing "
                          "state from "
                          "FIN_WAIT_1 to LAST_ACK\n");

            return PASS_ACTION;
        } else {
            // Still receiving packets
            ct_value->ttl = timestamp + TCP_FIN_WAIT;

            bpf_log_debug("[REV_DIRECTION] Failed FIN "
                          "check in "
                          "FIN_WAIT_2 state. Flags: %d. Seq: %d\n",
                          pkt->flags, ct_value->sequence);

            return PASS_ACTION;
        }
    }

    if (ct_value->state == LAST_ACK) {
        if ((pkt->flags & TCPHDR_ACK && pkt->seqN == ct_value->sequence) != 0) {
            // Ack to the last FIN.
            ct_value->state = TIME_WAIT;
            ct_value->ttl = timestamp + TCP_LAST_ACK;

            bpf_log_debug("[REV_DIRECTION] Changing "
                          "state from "
                          "LAST_ACK to TIME_WAIT\n");

            return PASS_ACTION;
        }
        // Still receiving packets
        ct_value->ttl = timestamp + TCP_LAST_ACK;

        return PASS_ACTION;
    }

    if (ct_value->state == TIME_WAIT) {
        if (pkt->connStatus == NEW) {

            return TCP_NEW;
        } else {
            // Let the packet go, but do not update timers.

            return PASS_ACTION;
        }
    }

    bpf_log_debug("[REV_DIRECTION] Should not get here. "
                  "Flags: %d. "
                  "State: %d. \n",
                  pkt->flags, ct_value->state);
    return PASS_ACTION;
}

static FORCE_INLINE int advance_tcp_state_machine_full(struct packetHeaders *pkt, uint8_t *ipRev,
                                                       uint8_t *portRev) {
    struct ct_v *value;
    struct ct_v newEntry = {0};
    struct ct_k key = {0};

    conntrack_get_key(&key, pkt, ipRev, portRev);

    /* == TCP  == */
    if (pkt->l4proto == IPPROTO_TCP) {
        // If it is a RST, label it as established.
        if ((pkt->flags & TCPHDR_RST) != 0) {
            // connections.delete(&key);
            return PASS_ACTION;
        }
        value = bpf_map_lookup_elem(&connections, &key);
        if (value != NULL) {
            return_action_t action;
            if ((value->ipRev == *ipRev) && (value->portRev == *portRev)) {
                action = handle_tcp_conntrack_forward(pkt, value, pkt->timestamp);
                if (action == TCP_NEW)
                    goto TCP_MISS;
                else
                    return PASS_ACTION;
            } else if ((value->ipRev != *ipRev) && (value->portRev != *portRev)) {
                action = handle_tcp_conntrack_reverse(pkt, value, pkt->timestamp);
                if (action == TCP_NEW)
                    goto TCP_MISS;
                else
                    return PASS_ACTION;
            } else {
                goto TCP_MISS;
            }
        }

    TCP_MISS:;
        // New entry. It has to be a SYN.
        if ((pkt->flags & TCPHDR_SYN) != 0 && (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
            newEntry.state = SYN_SENT;
            newEntry.ttl = pkt->timestamp + TCP_SYN_SENT;
            newEntry.sequence = pkt->seqN + HEX_BE_ONE;

            newEntry.ipRev = *ipRev;
            newEntry.portRev = *portRev;

            bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
            return PASS_ACTION;
        } else {
            // Validation failed
            bpf_log_debug("Validation failed %d\n", pkt->flags);
            return PASS_ACTION;
        }
    }

    // Not TCP packet
    return -1;
}

static FORCE_INLINE int advance_tcp_state_machine_local(struct ct_k *key, struct packetHeaders *pkt,
                                                        uint8_t *ipRev, uint8_t *portRev,
                                                        struct ct_v *value, bool *curr_value_set) {
    /* == TCP  == */
    if (pkt->l4proto == IPPROTO_TCP) {
        // If it is a RST, label it as established.
        if ((pkt->flags & TCPHDR_RST) != 0) {
            // connections.delete(&key);
            return PASS_ACTION;
        }
        if (value != NULL && *curr_value_set) {
            return_action_t action;
            if ((value->ipRev == *ipRev) && (value->portRev == *portRev)) {
                action = handle_tcp_conntrack_forward(pkt, value, pkt->timestamp);
                if (action == TCP_NEW)
                    goto TCP_MISS;
                else
                    return PASS_ACTION;
            } else if ((value->ipRev != *ipRev) && (value->portRev != *portRev)) {
                action = handle_tcp_conntrack_reverse(pkt, value, pkt->timestamp);
                if (action == TCP_NEW)
                    goto TCP_MISS;
                else
                    return PASS_ACTION;
            } else {
                goto TCP_MISS;
            }
        }

    TCP_MISS:;
        // New entry. It has to be a SYN.
        if ((pkt->flags & TCPHDR_SYN) != 0 && (pkt->flags | TCPHDR_SYN) == TCPHDR_SYN) {
            value->state = SYN_SENT;
            value->ttl = pkt->timestamp + TCP_SYN_SENT;
            value->sequence = pkt->seqN + HEX_BE_ONE;

            value->ipRev = *ipRev;
            value->portRev = *portRev;

            // bpf_map_update_elem(&connections, key, &newEntry, BPF_ANY);
            *curr_value_set = true;
            return PASS_ACTION;
        } else {
            // Validation failed
            bpf_log_debug("Validation failed %d\n", pkt->flags);
            return PASS_ACTION;
        }
    }

    // Not TCP packet
    return -1;
}

#endif // CONNTRACK_HELPERS_H_