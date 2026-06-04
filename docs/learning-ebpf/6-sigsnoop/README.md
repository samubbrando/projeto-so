# Introdução

Isso aqui sai bem mais do escopo do que a gente via e tenta fazer um código para unificar dois fluxos em um único dado, que seria, no caso, contabilizar a entrada e a saída obtida e representar ela.

## Fluxo

### 1. Definições
- Vamos ter um `event`, esse `event` pode ter um pid, tpid, sig, ret e comm.
    - Basicamente é o resultado final da análise.
    - Alguns que eu precisei de entender melhor:
        - sig: sinal enviado pelo sistema (tipo SIGKILL 9)
        - ret: valor de retorno da syscall (0 se der certo)
        - comm: eu já fiz isso no `netlink-proccess.c` e é o executável
- Primeiro `".maps"`:
    - Conexão do espaço do kernel para o espaço do usuário por meio de "hashs".
- Segundo `values`:
    - Ele é uma estrutura que será usada no `".maps"` do sistema
        - O primeiro atributo, tipo, indica isso (BPF_MAP_TYPE_HASH)
        - Além de tudo tem um "attaching" SEC(".maps")
    - Fora isso, as keys são __u32 (que eu não estou certo do que é, acredito que sequências inteiras de até 32 bits)
    - O tamanho máximo do mapa será de MAX_ENTRIES
    - Em resumo, é um mapa com keys __u32 que associa eventos de forma que tenha uma comunicação no user-space e o kernel de forma fluída, acredito que para permitir a alteração das partes múltiplas vezes.

### 2. Probes

Entry e Exit são bem simples, eles pegam os valores e atribuem para o map.

Agora quero separar elementos úteis para isso.

probe_entry:
```c
bpf_get_current_comm(
    event.comm, // Vai armazenar o resultado aqui 
    sizeof(event.comm)
);
bpf_map_update_elem(
    &values, // Vai armazenar nesse map que a gente fez
    &tid,    // Nessa key
    &event,  // O evento
    BPF_ANY  // Cria ou atualiza
);
```

probe_exit:
```c
bpf_map_lookup_elem(
    &values, // Nosso mapa 
    &tid     // Nossa key
);    
bpf_map_delete_elem(
    &values, // Nosso mapa   
    &tid     // Nossa key 
);
```

```c 
cleanup: // Isso aqui é uma label que é usada para limpeza
 bpf_map_delete_elem(&values, &tid);
 return 0;
``` 

### 3. Tracepoint

Só deixar claro que o ctx pode ter n atributos de n tipos.

Exemplos disso podem ser observados no código, mas aqui vou separar um deles:

```c
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
    pid_t tpid = (pid_t)ctx->args[0];
    int sig = (int)ctx->args[1];

    return probe_entry(tpid, sig);
}
```