#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_unlinkat")
int BPF_PROG(
    do_unlinktat,
    int dfd,
    struct filename *kernel_file
) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32; // Assim a gente pega somente o PID da thread atual.
    bpf_printk(
        "TESTE FENTRY/FEXIT | fentry: pid = %d, filename = %s\n", 
        pid, 
        kernel_file -> name // A gente não precisou fazer BPF_CORE_READ
    );

    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(
    do_unlinktat_exit,
    int dfd,
    struct filename *kernel_file,
    long ret
) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk(
        "TESTE FENTRY/FEXIT | fexit: pid = %d, filename = %s\n > RETURN: %ld\n", 
        pid, 
        kernel_file -> name, 
        ret
    );
    
    return 0;
}