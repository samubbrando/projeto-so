
#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>

#include <stdarg.h>

static int libbpf_print_fn(
        enum libbpf_print_level level,
        const char *fmt,
        va_list args) {
    return vfprintf(stderr, fmt, args);
}

int main() {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int err = 0;

    // Setta para depuracão futura
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    obj = bpf_object__open_file("rtt.bpf.o", NULL);

    if (!obj) {
        fprintf(stderr, "Falha na leitura do arquivo BPF (RTT)\n");
        err = 1;
        goto cleanup;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Falha para carregar (RTT)\n");
        err = 1;
        goto cleanup;    
    }

    prog = bpf_object__find_program_by_name(obj, "tcp_rcv");
    if (!prog) {
        fprintf(stderr, "Falha para achar o programa (tcp_rcv) no BPF (RTT);");
        err = 1;
        goto cleanup;    
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Criacão do link deu errado (RTT)!\n");
        err = 1;
        goto cleanup;
    }

    printf("Programa anexado! (RTT)\n");
    getchar();
    
    cleanup:
        bpf_link__destroy(link);
        bpf_object__close(obj);
        
    return err;
}
