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

#ifndef BPF_LOG_H_
#define BPF_LOG_H_

#include <stddef.h>
#include <string.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "conntrack_common.h"

#define DISABLED (0)
#define ERR (1)
#define WARNING (2)
#define NOTICE (3)
#define INFO (4)
#define DEBUG (5)

#define bpf_log_err(...)                                                       \
    (conntrack_cfg.log_level < ERR ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_warning(...)                                                   \
    (conntrack_cfg.log_level < WARNING ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_notice(...)                                                    \
    (conntrack_cfg.log_level < NOTICE ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_info(...)                                                      \
    (conntrack_cfg.log_level < INFO ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_debug(...)                                                     \
    (conntrack_cfg.log_level < DEBUG ? (0) : bpf_printk(__VA_ARGS__))

#endif // BPF_LOG_H_