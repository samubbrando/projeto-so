#!/bin/bash

set -e

BPF_SRC=src/bpf

echo "=== Compilando BPF RTT ==="
clang -O2 -g -target bpf -Isrc -c "$BPF_SRC/rtt.bpf.c" -o "$BPF_SRC/rtt.bpf.o" \
    -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types

echo "=== Gerando skeleton RTT ==="
bpftool gen skeleton "$BPF_SRC/rtt.bpf.o" > "$BPF_SRC/rtt.skel.h"

echo "=== Compilando BPF CGROUP_SKB ==="
clang -O2 -g -target bpf -Isrc -c "$BPF_SRC/cgroup_skb.bpf.c" -o "$BPF_SRC/cgroup_skb.bpf.o" \
    -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types

echo "=== Gerando skeleton CGROUP_SKB ==="
bpftool gen skeleton "$BPF_SRC/cgroup_skb.bpf.o" > "$BPF_SRC/cgroup_skb.skel.h"

echo "=== Compilando userspace ==="
clang -I/usr/include/x86_64-linux-gnu -Isrc -o rtt src/main.c -lbpf -lelf -lz

echo "=== Build concluído ==="