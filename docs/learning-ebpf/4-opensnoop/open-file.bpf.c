#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// int target = 925;
/* Isso aqui dá errado 
 * O eunomia não vai guardar esse cara na memória, dará erro
 * Esse valor vai ser definido em .data ou .bss (se for 0), só
 * que se cair em .data normal, esse compilador não consegue
 * acessar.
 */

/* Isso aqui não vai ser errado porque:
 * A parte const vai por isso em .rodata, ou seja, não vai ser
 * mexido pelo compilador em processo de otimização.
 * Volatile vai fazer o sistema buscar essa variável em memória,
 * porque não pode confiar a cópia.
 */
const volatile int target = 925; // Isso permite a gente alterar facilmente o skel.json

// Btw se for 0, ele vai pegar TODOS os programas, se você especificar algum ele só vai verificar para aquele PID.

/*
 * tracepoint/syscalls/sys_enter_openat
 * Me dá a chamada de abertura de arquivos
 */
SEC("tp/syscalls/sys_enter_openat")
int trace_open_file(
    struct trace_event_raw_sys_enter* ctx
) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    pid_t pid_target = (pid_t) target;

    if (pid_target && pid_target != pid) return 0;
    
    bpf_printk("(TARGET: %d) Process: %d tried to open a file\n", pid_target, pid);
    return 0;
}