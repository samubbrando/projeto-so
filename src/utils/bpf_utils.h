#ifndef BPF_UTILS_H
#define BPF_UTILS_H

#include <stdio.h>
#include <stdarg.h>
#include <bpf/libbpf.h>

static int bpf_print_fn(
    enum libbpf_print_level level,
    const char *fmt,
    va_list args)
{
    return vfprintf(stderr, fmt, args);
}

#endif
