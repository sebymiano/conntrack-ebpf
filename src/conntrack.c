// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>

#include <argparse.h>
#include <net/if.h>

#include "log.h"

#include "conntrack_if_helper.h"
#include "conntrack.skel.h"
#include "ebpf/conntrack_structs.h"

#define ONE_MILLION 1000000
#define ONE_BILLION 1000000000

static __u32 xdp_flags = 0;
static int ifindex_if1 = 0;
static int ifindex_if2 = 0;
static int connections_map_fd = 0;

static const char *const usages[] = {
    "conntrack [options] [[--] args]",
    "conntrack [options]",
    NULL,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static void cleanup_ifaces() {
    __u32 curr_prog_id = 0;

    if (ifindex_if1 != 0) {
        if (!bpf_xdp_query_id(ifindex_if1, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_if1, xdp_flags, NULL);
            }
        }
    }

    if (ifindex_if2 != 0) {
        if (!bpf_xdp_query_id(ifindex_if2, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_if2, xdp_flags, NULL);
            }
        }
    }
}

void sigint_handler(int sig_no) {
    log_debug("Closing program...");
    cleanup_ifaces();
    exit(0);
}

static void poll_stats(int map_fd, int interval, int duration, FILE *out_fp) {
    unsigned int nr_cpus = libbpf_num_possible_cpus();
    struct pkt_md values[nr_cpus];
    __u64 prev[2] = {0};
    int i;
    int tot_duration = 0;

    if (out_fp != NULL) {
        fprintf(out_fp, "Seconds,RX-packets,RX-bytes\n");
    }
    while (1) {
        __u32 key = 0;
        float bit_rate, rate;
        sleep(interval);

        __u64 sum[2] = {0};

        assert(bpf_map_lookup_elem(map_fd, &key, values) == 0);
        for (i = 0; i < nr_cpus; i++) {
            sum[0] += values[i].cnt;
            sum[1] += values[i].bytes_cnt;
        }
        if (sum[0] > prev[0]) {
            rate = (sum[0] - prev[0]) / interval;
            log_info("%10llu pkt/s (%.2f Mpps)", (sum[0] - prev[0]) / interval, rate / ONE_MILLION);
        }
        if (sum[1] > prev[1]) {
            bit_rate = ((sum[1] - prev[1]) / interval) * 8;
            log_info("%10llu byte/s (%.2f Gbps)", (sum[1] - prev[1]) / interval,
                     bit_rate / ONE_BILLION);
        }

        if (sum[0] > prev[0] && sum[1] > prev[1]) {
            if (out_fp != NULL) {
                fprintf(out_fp, "%d,%.2f,%.2f\n", tot_duration, rate, bit_rate);
            }
        }

        prev[0] = sum[0];
        prev[1] = sum[1];
        tot_duration++;
        if (duration > 0 && tot_duration > duration) {
            return;
        }
    }
}

int main(int argc, const char **argv) {
    struct conntrack_bpf *skel;
    int err;
    int use_spinlocks = 0;
    int enable_promiscuous = 0;
    const char *if1 = NULL;
    const char *if2 = NULL;
    const char *if2_dst_mac = NULL;
    const char *output_file = NULL;
    int metadata_map_fd;
    int duration = -1;
    int redirect_same_iface = 0;
    int quiet = 0;

    // Disabled by default
    int log_level = 0;

    unsigned char if1_mac[6];
    unsigned char if2_mac[6];
    unsigned char if2_dst_mac_byte[6];

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_BOOLEAN('s', "spin_locks", &use_spinlocks, "Disable spin locks", NULL, 0, 0),
        OPT_BOOLEAN('p', "promiscuous", &enable_promiscuous,
                    "Enable promiscuous mode on all interfaces", NULL, 0, 0),
        OPT_STRING('1', "iface1", &if1, "Interface to receive packet from", NULL, 0, 0),
        OPT_STRING('2', "iface2", &if2, "Interface to redirect packet to", NULL, 0, 0),
        OPT_STRING('m', "if2_dst_mac", &if2_dst_mac,
                   "When specify the if2, we need to know the dst MAC", NULL, 0, 0),
        OPT_INTEGER('l', "log_level", &log_level, "Log level", NULL, 0, 0),
        OPT_INTEGER('d', "duration", &duration, "Duration of the experiment", NULL, 0, 0),
        OPT_BOOLEAN('r', "redir_same_iface", &redirect_same_iface, "Redirect packet back on iface1",
                    NULL, 0, 0),
        OPT_BOOLEAN('q', "quiet", &quiet, "Do not print stats", NULL, 0, 0),
        OPT_STRING('o', "out_file", &output_file, "Save results into an output csv file", NULL, 0,
                   0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse,
                      "\nThis software attaches an XDP program that emulates the behavior of "
                      "Linux conntrack to the interface specified in the 'iface1' "
                      "argument.scription of what the program does and how it works.",
                      "\nIf 'iface2' argument is specified, packets are redirected to that "
                      "interface instead of dropping them.");
    argc = argparse_parse(&argparse, argc, argv);

    if (use_spinlocks) {
        log_trace("Spinlocks are DISABLED");
        use_spinlocks = 0;
    } else {
        log_trace("Spinlocks are ENABLED");
        use_spinlocks = 1;
    }

    if (enable_promiscuous) {
        log_trace("Promiscuous mode is ENABLED");
    } else {
        log_trace("Promiscuous mode is DISABLED");
    }

    if (redirect_same_iface) {
        log_trace("Redirect on the same interface (XDP_TX) mode is ENABLED");
    } else {
        log_trace("Redirect on the same interface (XDP_TX) mode is DISABLED");
    }

    if (quiet) {
        log_trace("Quiet mode is ENABLED (do NOT print and gather stats from the data plane)");
        if (output_file != NULL) {
            log_error("The QUIET mode is not compatible with the output file");
            exit(1);
        }
    } else {
        log_trace("Quiet mode is DISABLED (print and gather stats from the data plane)");
    }

    if (if1 != NULL) {
        log_info("XDP program will be attached to %s interface", if1);
        ifindex_if1 = if_nametoindex(if1);
        if (!ifindex_if1) {
            log_fatal("Error while retrieving the ifindex of %s", if1);
            exit(1);
        } else {
            log_info("Got ifindex for iface: %s, which is %d", if1, ifindex_if1);
        }

        if (get_mac_from_iface_name(if1, if1_mac) != 0) {
            log_fatal("Error while retrieving the MAC of %s", if1);
            exit(1);
        } else {
            log_info("Got MAC for iface: %s, which is %02x:%02x:%02x:%02x:%02x:%02x", if1,
                     if1_mac[0], if1_mac[1], if1_mac[2], if1_mac[3], if1_mac[4], if1_mac[5]);
        }
    } else {
        log_error("Error, you must specify the interface where to attach the XDP "
                  "program");
        exit(1);
    }

    if (if2 != NULL) {
        if (redirect_same_iface) {
            log_error("You cannot redirect on the same interface and specify the iface2");
            exit(1);
        }

        if (if2_dst_mac == NULL) {
            log_warn("Dst MAC not specified, I will generate a random MAC");
            if (gen_random_mac(if2_dst_mac_byte) != 0) {
                log_error("Unable to generate a random MAC. Exit");
                exit(1);
            }
        } else {
            if (mac_str_to_byte_array(if2_dst_mac_byte, if2_dst_mac) != 0) {
                log_error("Wrong format of MAC address: %s", if2_dst_mac);
                exit(1);
            }
        }
        log_debug("Redirect mode is enabled. Packets will be redirected to %s "
                  "interface",
                  if2);

        ifindex_if2 = if_nametoindex(if2);
        if (!ifindex_if2) {
            log_fatal("Error while retrieving the ifindex of %s", if2);
            exit(1);
        } else {
            log_info("Got ifindex for iface: %s, which is %d", if2, ifindex_if2);
        }

        if (get_mac_from_iface_name(if2, if2_mac) != 0) {
            log_fatal("Error while retrieving the MAC of %s", if2);
            exit(1);
        } else {
            log_info("Got MAC for iface: %s, which is %02x:%02x:%02x:%02x:%02x:%02x", if2,
                     if2_mac[0], if2_mac[1], if2_mac[2], if2_mac[3], if2_mac[4], if2_mac[5]);
        }
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (log_level > 0) {
        /* Set up libbpf errors and debug info callback */
        libbpf_set_print(libbpf_print_fn);
    }

    /* Open BPF application */
    skel = conntrack_bpf__open();
    if (!skel) {
        log_error("Failed to open BPF skeleton");
        return 1;
    }

    // Setup config for this program
    skel->rodata->conntrack_cfg.log_level = log_level;
    skel->rodata->conntrack_cfg.if_index_if1 = ifindex_if1;
    skel->rodata->conntrack_cfg.if_index_if2 = ifindex_if2;
    skel->rodata->conntrack_cfg.enable_spin_locks = use_spinlocks;
    skel->rodata->conntrack_cfg.redirect_same_iface = redirect_same_iface;
    skel->rodata->conntrack_cfg.quiet = quiet;

    // This is not used
    memcpy(skel->rodata->conntrack_mac_cfg.if1_src_mac, if1_mac, 6);

    if (ifindex_if2 != 0) {
        memcpy(skel->rodata->conntrack_mac_cfg.if2_src_mac, if2_mac, 6);
        memcpy(skel->rodata->conntrack_mac_cfg.if2_dst_mac, if2_dst_mac_byte, 6);
    }

    bpf_program__set_type(skel->progs.xdp_conntrack_prog, BPF_PROG_TYPE_XDP);

    if (ifindex_if2 != 0) {
        bpf_program__set_type(skel->progs.xdp_redirect_dummy_prog, BPF_PROG_TYPE_XDP);
    }

    err = conntrack_bpf__load(skel);
    if (err) {
        log_error("Failed to load XDP program");
        goto cleanup;
    }

    metadata_map_fd = bpf_map__fd(skel->maps.metadata);
    connections_map_fd = bpf_map__fd(skel->maps.connections);

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;

    if (sigaction(SIGINT, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    if (sigaction(SIGTERM, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;
    set_iface_up(if1);

    if (enable_promiscuous) {
        enable_promisc(if1);
    }

    err = bpf_xdp_attach(ifindex_if1, bpf_program__fd(skel->progs.xdp_conntrack_prog), xdp_flags,
                         NULL);
    if (err) {
        log_error("Failed to attach XDP program on: %s", if1);
        goto cleanup;
    }

    if (ifindex_if2 != 0) {
        xdp_flags = 0;
        xdp_flags |= XDP_FLAGS_DRV_MODE;
        set_iface_up(if2);
        if (enable_promiscuous) {
            enable_promisc(if2);
        }
        err = bpf_xdp_attach(ifindex_if2, bpf_program__fd(skel->progs.xdp_redirect_dummy_prog),
                             xdp_flags, NULL);
        if (err) {
            log_error("Failed to attach XDP program on: %s", if2);
            goto cleanup;
        }
    }

    log_info("Successfully started!");

    sleep(1);

    if (output_file != NULL) {
        FILE *out_fp = NULL;
        out_fp = fopen(output_file, "w");

        if (out_fp == NULL) {
            log_error("Unable to open file %s", output_file);
            goto cleanup;
        }
        log_debug("Results will be save into file: %s", output_file);
        poll_stats(metadata_map_fd, 1, duration, out_fp);
        fclose(out_fp);
    } else {
        poll_stats(metadata_map_fd, 1, duration, NULL);
    }

cleanup:
    cleanup_ifaces();
    conntrack_bpf__destroy(skel);
    log_info("Program stopped correctly");
    return -err;
}
