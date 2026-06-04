// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_syscalls_sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    // Variáveis
    u64 id;
    pid_t pid, tgid;
    struct event event={0};
    struct task_struct *task;

    // Obtém o user_id associado ao processo atual 
    uid_t uid = (u32)bpf_get_current_uid_gid();
    id = bpf_get_current_pid_tgid(); // Atribui o id total do processo atual
    tgid = id >> 32;                 // Isola o tgid (main proccess id)
    
    task = (struct task_struct*) bpf_get_current_task(); // Obtém a task

    event.pid = tgid;
    event.uid = uid;
    /* BPF_CORE_READ só permite a gente acessar atributos de estruturas
     * de maneira protegida, então os campos após a primeira linha são mais 
     * atributos que estamos lendo em cascata, L1->L2->L3
     */ 
    event.ppid = BPF_CORE_READ(
        task,         // Ponteiro inicial (struct task_struct *)
        real_parent,  // Aponta para a task_struct do pai (task->real_parent)
        tgid          // Pega o TGID do pai (que é o PPID do filho) (task->real_parent->tgid)
    );
    
    char *cmd_ptr = (char *) BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_str(
        &event.comm, 
        sizeof(event.comm), 
        cmd_ptr
    );
    bpf_perf_event_output(
        ctx, 
        &events, 
        BPF_F_CURRENT_CPU, 
        &event, 
        sizeof(event)
    );
    return 0;
}

char LICENSE[] SEC("license") = "GPL";