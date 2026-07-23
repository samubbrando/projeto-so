#ifndef BPF_COMMON_H
#define BPF_COMMON_H

#include "common/monitor.h"
#include <bpf/bpf_helpers.h>

static __always_inline void refill_bucket(struct rate_bucket *bucket)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - bucket->last_ns;
    __u64 added = (bucket->rate_bps * elapsed) / 8000000000ULL;
    bucket->tokens += added;
    if (bucket->tokens > bucket->burst)
        bucket->tokens = bucket->burst;
    bucket->last_ns = now;
}

#endif
