// Esse script é do repositório de tutorial

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";


// Aqui eu tô attachando a função para esse tracepoint
// Eu tô gostando de pensar que o código eBPF se assemelha ao código de uma API REST,
// a gente aloca uma função para uma "rota" e a partir dessa rota vamos poder obter
// o retorno dela.

// O template é "tp" pq é tracepoint + "syscalls" pq é o subsistema + 
// + "sys_enter_write" porque é o evento específico.

// Para saber os tracepoints disponibilizados pelo SO: 
// sudo ls /sys/kernel/debug/tracing/events/syscalls/
SEC("tp/syscalls/sys_enter_write") 
int handle_tp(
    void *ctx // Dados específicos do tracepoint com o qual estamos trabalhando
)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (pid_filter && pid != pid_filter)
        return 0;
    // Isso é um "print de debug"
    // bpf_printk -> /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);

    // Drawbacks: esse recurso é compartilhado para todo o sistema operacional
    // então todos os programas tem acesso a esse recurso

    // Aceita até 3 parâmetros, o que até agora não ficou claro como seria um
    // problema porque eu posso formatar a string antes.
    return 0;
}
