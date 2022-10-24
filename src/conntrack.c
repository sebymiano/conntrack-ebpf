// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <xdp/prog_dispatcher.h>
#include <xdp/libxdp.h>
#include <fcntl.h>
#include <signal.h>

#include <argparse.h>
#include <net/if.h>
#include "conntrack_if_helper.h"

#include "conntrack.skel.h"

static struct xdp_program *xdp_prog_;
static bool attached = false;
static int ifindex_if1 = 0;

static const char *const usages[] = {
    "conntrack [options] [[--] args]",
    "conntrack [options]",
    NULL,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

void sigint_handler(int sig_no) {
    printf("\nClosing program...\n");
    if (attached) {
        xdp_program__detach(xdp_prog_, ifindex_if1, XDP_MODE_NATIVE, 0);
    }
    xdp_program__close(xdp_prog_);
    // conntrack_bpf__destroy(skel);
    exit(0);
}

int main(int argc, const char **argv) {
    struct conntrack_bpf *skel;
    // struct xdp_program *xdp_prog_;
    int err;
    int use_spinlocks = 0;
    const char *if1 = NULL;
    const char *if2 = NULL;
    int ifindex_if2 = 0;
    int debug_level = 0;

    char if1_mac[32];
    char if2_mac[32];

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_BOOLEAN('s', "spin_locks", &use_spinlocks, "Use spin locks", NULL,
                    0, 0),
        OPT_STRING('1', "iface1", &if1, "Interface to receive packet from",
                   NULL, 0, 0),
        OPT_STRING('2', "iface2", &if2, "Interface to redirect packet to", NULL,
                   0, 0),
        OPT_INTEGER('d', "debug", &debug_level, "Debug level", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(
        &argparse,
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
            printf("Got ifindex for iface: %s, which is %d\n", if1,
                   ifindex_if1);
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
            printf("Got ifindex for iface: %s, which is %d\n", if2,
                   ifindex_if2);
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
    skel->rodata->conntrack_cfg.log_level = debug_level;
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

    xdp_prog_ = xdp_program__from_bpf_obj(skel->obj, "xdp_conntrack");
    err = xdp_program__attach(xdp_prog_, ifindex_if1, XDP_MODE_NATIVE, 0);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program");
        goto cleanup;
    } else {
        attached = true;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;

    if (sigaction(SIGINT, &action, NULL) == -1) {
        fprintf(stderr, "sigation failed\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat "
           "/sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    for (;;) {
        /* trigger our BPF program */
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    if (attached) {
        xdp_program__detach(xdp_prog_, ifindex_if1, XDP_MODE_NATIVE, 0);
    }
    xdp_program__close(xdp_prog_);
    conntrack_bpf__destroy(skel);
    return -err;
}
