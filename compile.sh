#!/bin/bash

clang -O2 -g -target bpf -c src/rtt.bpf.c -o src/rtt.bpf.o \
    -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types

bpftool gen skeleton src/rtt.bpf.o > src/rtt.skel.h

clang -I/usr/include/x86_64-linux-gnu -o rtt src/main.c -lbpf -lelf -lz
