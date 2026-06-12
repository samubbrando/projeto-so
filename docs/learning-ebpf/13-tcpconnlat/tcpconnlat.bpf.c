// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "tcpconnlat.h"

#define AF_INET    2
#define AF_INET6   10

const volatile __u64 targ_min_us = 0;
const volatile pid_t targ_tgid = 0;

struct piddata {
  char comm[TASK_COMM_LEN];
  u64 ts;
  u32 tgid;
};


// MAP de START, SOCKET e momento de chamada para início de
// conexão feita pelo PROCESSO. (Quando chama um connect())
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct sock *);
  __type(value, struct piddata);
} start SEC(".maps"); 

// Isso aqui é um MAP de PERF_EVENT_ARRAY (ler 7-execsnoop)
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

// kprobe de tcp_v4_connect e tcp_v6_connect
static int trace_connect(struct sock *sk)
{
  // Obtém o pid
  u32 tgid = bpf_get_current_pid_tgid() >> 32;
  struct piddata piddata = {};

  if (targ_tgid && targ_tgid != tgid)
    return 0;

  // Identifica o executável
  bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));
  
  // Obtém o tempo de inicialização
  piddata.ts = bpf_ktime_get_ns();
  piddata.tgid = tgid;

  // Atribui
  bpf_map_update_elem(&start, &sk, &piddata, 0);
  return 0;
}

// kprobe para detectar quando processa um SYN-ACK (tcp_rcv_state_process) 
// Se o nosso registro estiver SYN-SENT, ele vai e skippa porque ainda não
// foi finalizado totalmente, está no processo do handshake.
static int handle_tcp_rcv_state_process(void *ctx, struct sock *sk)
{
  struct piddata *piddatap;
  struct event event = {};
  s64 delta;
  u64 ts;
  
  // Verifica se o socket ainda está no estado SYN_SENT
  if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
    return 0;

  // Pega o elemento
  piddatap = bpf_map_lookup_elem(&start, &sk);
  if (!piddatap)
    return 0;

  // Calcula o tempo atual
  ts = bpf_ktime_get_ns();
  delta = (s64)(ts - piddatap->ts); // Variação -> LATÊNCIA
  if (delta < 0)
    goto cleanup;

  event.delta_us = delta / 1000U; // (em microssegundos)
  if (targ_min_us && event.delta_us < targ_min_us)
    goto cleanup;
  __builtin_memcpy(&event.comm, piddatap->comm,
      sizeof(event.comm));
  
  // Atribui as métricas do recebimento
  event.ts_us = ts / 1000;
  event.tgid = piddatap->tgid;
  event.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
  event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
  event.af = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (event.af == AF_INET) {
    event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  } else {
    BPF_CORE_READ_INTO(&event.saddr_v6, sk,
        __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&event.daddr_v6, sk,
        __sk_common.skc_v6_daddr.in6_u.u6_addr32);
  }

  // Bota as informações no PERF EVENT buffer
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
      &event, sizeof(event));

cleanup:
  bpf_map_delete_elem(&start, &sk);
  return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
  return trace_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
  return trace_connect(sk);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock *sk)
{
  return handle_tcp_rcv_state_process(ctx, sk);
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk)
{
  return trace_connect(sk);
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(fentry_tcp_v6_connect, struct sock *sk)
{
  return trace_connect(sk);
}

SEC("fentry/tcp_rcv_state_process")
int BPF_PROG(fentry_tcp_rcv_state_process, struct sock *sk)
{
  return handle_tcp_rcv_state_process(ctx, sk);
}

char LICENSE[] SEC("license") = "GPL";