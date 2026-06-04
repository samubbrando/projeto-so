#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ISSO é o que permite nosso código rodar no kernel
char LICENSE[] SEC("license") = "Dual BSD/GPL"; 


SEC("kprobe/do_unlinkat")
int BPF_KPROBE( // Isso aqui é um "macro"
    do_unlinkat,                       // Função que vamos interceptar
    int dfd,                           // Descritor do arquivo
    struct filename *filename_kernel   // Nome do arquivo
) // Função de probe
{
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    // A gente não pode só ler o nome, tipo filename_kernel->name
    // O BPF tá lendo do kernel, então ele não roda livremente, ele roda numa camada
    // um pouco mais restrita
    filename = BPF_CORE_READ(filename_kernel, name); // Lemos o nome do arquivo na memória do kernel
    
    bpf_printk("TESTE DE KPROBE ENTRY: pid = %d, filename = %s\n", pid, filename);
    return 0;
}

SEC("kretprobe/do_unlinkat") // Vamos ler o retorno da função que pegamos
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("TESTE DE KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}