#ifndef RTT_H
#define RTT_H

#include <stdio.h>
#include <bpf/libbpf.h>
#include <stdarg.h>
#include "rtt.skel.h"

static int libbpf_print_fn(
        enum libbpf_print_level level,
        const char *fmt,
        va_list args) {
    return vfprintf(stderr, fmt, args);
}

static struct rtt_bpf* init_bpf(void) {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    struct rtt_bpf *skel = rtt_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Falha ao abrir/carregar BPF (RTT)\n");
        return NULL;
    }

    printf("Programa BPF carregado!\n");
    return skel;
}

static int attach_bpf(struct rtt_bpf *skel) {
    if (rtt_bpf__attach(skel)) {
        fprintf(stderr, "Falha ao anexar BPF (RTT)\n");
        return 1;
    }

    printf("Programa BPF anexado!\n");
    return 0;
}

static void cleanup_bpf(struct rtt_bpf *skel) {
    rtt_bpf__destroy(skel);
}

#endif
