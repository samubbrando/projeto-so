#ifndef RTT_H
#define RTT_H

#include <bpf/libbpf.h>
#include "utils/bpf_utils.h"
#include "bpf/rtt.skel.h"

static struct rtt_bpf *init_rtt(void)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(bpf_print_fn);

    struct rtt_bpf *skel = rtt_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failure opening/loading BPF (RTT)\n");
        return NULL;
    }

    printf("BPF program loaded (RTT)!\n");
    return skel;
}

static int attach_rtt(struct rtt_bpf *skel)
{
    if (rtt_bpf__attach(skel))
    {
        fprintf(stderr, "Failure attaching BPF (RTT)\n");
        return 1;
    }

    printf("BPF program attached (RTT)!\n");
    return 0;
}

static void cleanup_rtt(struct rtt_bpf *skel)
{
    rtt_bpf__destroy(skel);
}

#endif
