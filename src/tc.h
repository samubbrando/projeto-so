#ifndef TC_H
#define TC_H

#include <bpf/libbpf.h>
#include <stdarg.h>
#include <net/if.h>
#include "utils/bpf_utils.h"
#include "bpf/tc.skel.h"
#include "common/monitor.h"
#include "net-funcs.h"

static struct tc_bpf *init_tc(void)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(bpf_print_fn);

    struct tc_bpf *skel = tc_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failure opening/loading BPF (TC)\n");
        return NULL;
    }

    printf("BPF program loaded (TC)!\n");
    return skel;
}

static int attach_tc_egress(struct tc_bpf *skel, const char *iface)
{
    if (!iface)
    {
        iface = detect_default_iface();
        if (!iface)
        {
            fprintf(stderr, "Could not detect default interface\n");
            return 1;
        }
    }

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0)
    {
        fprintf(stderr, "Invalid interface: %s\n", iface);
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_tcx(
        skel->progs.tc_egress, ifindex, NULL);
    if (!link)
    {
        fprintf(stderr, "Failure attaching TC egress to %s\n", iface);
        return 1;
    }

    skel->links.tc_egress = link;
    printf("TC egress attached to %s!\n", iface);
    return 0;
}

static int read_tc_egress(struct tc_bpf *skel, struct egress_stats *stats)
{
    int ncpus = libbpf_num_possible_cpus();
    struct egress_stats percpu_stats[ncpus];
    __u32 key = 0;

    if (bpf_map__lookup_elem(skel->maps.egress_map, &key, sizeof(key),
                             percpu_stats,
                             sizeof(struct egress_stats) * ncpus, 0) != 0)
    {
        fprintf(stderr, "Failed to read egress stats from BPF map\n");
        return -1;
    }

    memset(stats, 0, sizeof(*stats));
    for (int i = 0; i < ncpus; i++)
    {
        stats->packets += percpu_stats[i].packets;
        stats->bytes   += percpu_stats[i].bytes;
    }

    return 0;
}

static void cleanup_tc(struct tc_bpf *skel)
{
    tc_bpf__destroy(skel);
}

#endif
