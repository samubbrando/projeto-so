#!/bin/bash

set -e

BPF_SRC=src/bpf

echo "=== Compilando BPF RTT ==="
clang -O2 -g -target bpf -Isrc -c "$BPF_SRC/rtt.bpf.c" -o "$BPF_SRC/rtt.bpf.o" \
    -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types

echo "=== Gerando skeleton RTT ==="
bpftool gen skeleton "$BPF_SRC/rtt.bpf.o" > "$BPF_SRC/rtt.skel.h"

echo "=== Compilando BPF XDP ==="
clang -O2 -g -target bpf -Isrc -c "$BPF_SRC/xdp.bpf.c" -o "$BPF_SRC/xdp.bpf.o" \
    -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types

echo "=== Gerando skeleton XDP ==="
bpftool gen skeleton "$BPF_SRC/xdp.bpf.o" > "$BPF_SRC/xdp.skel.h"

echo "=== Compilando BPF TC ==="
clang -O2 -g -target bpf -Isrc -c "$BPF_SRC/tc.bpf.c" -o "$BPF_SRC/tc.bpf.o" \
    -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types

echo "=== Gerando skeleton TC ==="
bpftool gen skeleton "$BPF_SRC/tc.bpf.o" > "$BPF_SRC/tc.skel.h"

echo "=== Compilando userspace ==="
clang -I/usr/include/x86_64-linux-gnu -Isrc -o rtt src/main.c -lbpf -lelf -lz

echo "=== Build concluído ==="
