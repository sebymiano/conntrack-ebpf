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

#include "conntrack_if_helper.h"
#include "conntrack.skel.h"

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

    if (!bpf_xdp_query_id(ifindex_if1, xdp_flags, &curr_prog_id)) {
        if (curr_prog_id) {
            bpf_xdp_detach(ifindex_if1, xdp_flags, NULL);
        }
    }

    if (!bpf_xdp_query_id(ifindex_if2, xdp_flags, &curr_prog_id)) {
        if (curr_prog_id) {
            bpf_xdp_detach(ifindex_if2, xdp_flags, NULL);
        }
    }
}

void sigint_handler(int sig_no) {
    printf("\nClosing program...\n");
    cleanup_ifaces();
    exit(0);
}

static void poll_stats(int map_fd, int interval, int duration) {
    unsigned int nr_cpus = libbpf_num_possible_cpus();
    __u64 values[nr_cpus];
    __u64 prev = 0;
    int i;
    int tot_duration = 0;

    while (1) {
        __u32 key = 0;

        sleep(interval);

        __u64 sum = 0;

        assert(bpf_map_lookup_elem(map_fd, &key, values) == 0);
        for (i = 0; i < nr_cpus; i++)
            sum += values[i];
        if (sum > prev)
            printf("%10llu pkt/s\n", (sum - prev) / interval);
        prev = sum;
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
    const char *if1 = NULL;
    const char *if2 = NULL;
    int log_level = 0;
    int metadata_map_fd;
    int duration = -1;
    // int interval = 10;

    char if1_mac[32];
    char if2_mac[32];
    // const char *output = NULL;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_BOOLEAN('s', "spin_locks", &use_spinlocks, "Use spin locks", NULL, 0, 0),
        OPT_STRING('1', "iface1", &if1, "Interface to receive packet from", NULL, 0, 0),
        OPT_STRING('2', "iface2", &if2, "Interface to redirect packet to", NULL, 0, 0),
        // OPT_STRING('o', "output", &output, "Dump content of connections map
        // into output file", NULL, 0, 0),
        OPT_INTEGER('l', "log_level", &log_level, "Log level", NULL, 0, 0),
        OPT_INTEGER('d', "duration", &duration, "Duration of the experiment", NULL, 0, 0),
        // OPT_INTEGER('i', "interval", &interval, "Interval on which results
        // will be saved into the output file", NULL, 0, 0),
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

    if (if1 != NULL) {
        printf("XDP program will be attached to %s interface\n", if1);
        ifindex_if1 = if_nametoindex(if1);
        if (!ifindex_if1) {
            printf("Error while retrieving the ifindex of %s\n", if1);
            exit(1);
        } else {
            printf("Got ifindex for iface: %s, which is %d\n", if1, ifindex_if1);
        }

        if (get_mac_from_iface_name(if1, if1_mac) != 0) {
            printf("Error while retrieving the MAC of %s\n", if1);
            exit(1);
        } else {
            printf("Got MAC for iface: %s, which is %s\n", if1, if1_mac);
        }
    } else {
        printf("Error, you must specify the interface where to attach the XDP "
               "program\n");
        exit(1);
    }

    if (if2 != NULL) {
        printf("Redirect mode is enabled. Packets will be redirected to %s "
               "interface\n",
               if2);

        ifindex_if2 = if_nametoindex(if2);
        if (!ifindex_if2) {
            printf("Error while retrieving the ifindex of %s\n", if2);
            exit(1);
        } else {
            printf("Got ifindex for iface: %s, which is %d\n", if2, ifindex_if2);
        }

        if (get_mac_from_iface_name(if2, if2_mac) != 0) {
            printf("Error while retrieving the MAC of %s\n", if2);
            exit(1);
        } else {
            printf("Got MAC for iface: %s, which is %s\n", if2, if2_mac);
        }
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = conntrack_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Setup config for this program
    skel->rodata->conntrack_cfg.log_level = log_level;
    skel->rodata->conntrack_cfg.if_index_if1 = ifindex_if1;
    skel->rodata->conntrack_cfg.if_index_if2 = ifindex_if2;
    skel->rodata->conntrack_cfg.enable_spin_locks = use_spinlocks;

    // unsigned int mac_array[6];
    // if (!mac_str_to_byte_array(mac_array, if1_mac)) {
    //     goto cleanup;
    // }
    // memcpy(skel->rodata->conntrack_mac_cfg.if1_dst_mac, mac_array, 6);

    // if (ifindex_if2 != 0) {
    //     if (!mac_str_to_byte_array(mac_array, if2_mac)) {
    //         goto cleanup;
    //     }
    //     memcpy(skel->rodata->conntrack_mac_cfg.if2_dst_mac, mac_array, 6);
    // }

    bpf_program__set_type(skel->progs.xdp_conntrack_prog, BPF_PROG_TYPE_XDP);

    if (ifindex_if2 != 0) {
        bpf_program__set_type(skel->progs.xdp_redirect_dummy_prog, BPF_PROG_TYPE_XDP);
    }

    err = conntrack_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load XDP program");
        goto cleanup;
    }

    metadata_map_fd = bpf_map__fd(skel->maps.metadata);
    connections_map_fd = bpf_map__fd(skel->maps.connections);

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;

    if (sigaction(SIGINT, &action, NULL) == -1) {
        fprintf(stderr, "sigation failed\n");
        goto cleanup;
    }

    if (sigaction(SIGTERM, &action, NULL) == -1) {
        fprintf(stderr, "sigation failed\n");
        goto cleanup;
    }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;
    set_iface_up(if1);
    err = bpf_xdp_attach(ifindex_if1, bpf_program__fd(skel->progs.xdp_conntrack_prog), xdp_flags,
                         NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program on: %s", if1);
        goto cleanup;
    }

    if (ifindex_if2 != 0) {
        xdp_flags = 0;
        xdp_flags |= XDP_FLAGS_DRV_MODE;
        set_iface_up(if2);
        err = bpf_xdp_attach(ifindex_if2, bpf_program__fd(skel->progs.xdp_redirect_dummy_prog),
                             xdp_flags, NULL);
        if (err) {
            fprintf(stderr, "Failed to attach XDP program on: %s", if2);
            goto cleanup;
        }
    }

    printf("Successfully started! Please run `sudo cat "
           "/sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    sleep(500);
    poll_stats(metadata_map_fd, 1, duration);

cleanup:
    cleanup_ifaces();
    bpf_object__close(skel->obj);
    conntrack_bpf__destroy(skel);
    return -err;
}
