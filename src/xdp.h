#ifndef XDP_H
#define XDP_H

#include <bpf/libbpf.h>
#include <stdarg.h>
#include <net/if.h>
#include "utils/bpf_utils.h"
#include "bpf/xdp.skel.h"
#include "common/monitor.h"

static struct xdp_bpf *init_xdp(void)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(bpf_print_fn);

    struct xdp_bpf *skel = xdp_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failure opening/loading BPF (XDP)\n");
        return NULL;
    }

    printf("BPF program loaded (XDP)!\n");
    return skel;
}

static int attach_xdp(struct xdp_bpf *skel, const char *iface)
{
    struct bpf_program *prog = skel->progs.xdp_ingress;
    if (!prog)
    {
        fprintf(stderr, "XDP ingress program not found\n");
        return 1;
    }

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0)
    {
        fprintf(stderr, "Invalid interface: %s\n", iface);
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
    if (!link)
    {
        fprintf(stderr, "Failure attaching XDP program to interface %s\n", iface);
        return 1;
    }

    skel->links.xdp_ingress = link;

    printf("BPF program attached (XDP)!\n");
    return 0;
}

static void cleanup_xdp(struct xdp_bpf *skel)
{
    xdp_bpf__destroy(skel);
}

static int read_xdp_ingress(struct xdp_bpf *skel, struct ingress_stats *stats)
{
    int ncpus = libbpf_num_possible_cpus();
    struct ingress_stats percpu_stats[ncpus];
    __u32 key = 0;

    if (bpf_map__lookup_elem(skel->maps.ingress_map, &key, sizeof(key),
                             percpu_stats, sizeof(struct ingress_stats) * ncpus, 0) != 0)
    {
        fprintf(stderr, "Failed to read ingress stats from BPF map\n");
        return -1;
    }

    memset(stats, 0, sizeof(*stats));
    for (int i = 0; i < ncpus; i++)
    {
        stats->packets += percpu_stats[i].packets;
        stats->bytes += percpu_stats[i].bytes;
    }

    return 0;
}
#endif