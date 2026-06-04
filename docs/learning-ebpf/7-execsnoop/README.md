# Introdução

Nossas saídas são através do `bpf_printk` e toda vez precisamos verificar as sinalizações enviadas através do `/sys/kernel/debug/tracing/trace_pipe`.

A gente agora vai tentar mandar a saída para um buffer e acessar ele em outro ponto através de uma estrutura de dados apropriada.

Isso é feito através de arrays de evento.

O que vamos trabalhar vai ser o `perf event array`.

## Fluxo

Primeiro preciamos entender como mapeamos esse buffer no nosso código.

É interessante lembrar do map do último tutorial, a gente vai definir uma estrutura semelhante para poder mapear eventos também.


### 0. Definição da nossa estrutura

A gente vai criar uma nova estrutura `__EXECSNOOP_H`.

Essa estrutura quando definida vai fazer os passos de definir uma estrutura `event` com os atributos:

```c
struct event {
    int pid;
    int ppid;
    int uid;
    int retval;
    bool is_exit;
    char comm[TASK_COMM_LEN];
};
```

### 1. Definição do Event Array

Isso aqui é simples, inicializamos o `perf event array` com essas linhas e colocamos um nome, não demanda muita especificação. 

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");
```

### 2. Usando Event Array

Eu reorganizei o código para ficar mais compreensível para explicar os passos de preparação, mas o código relativo a essa etapa:

```c
bpf_perf_event_output( // Saída para o perf_array
    ctx,               // Evento que engatilhou chamada
    &events,           // Map do perf_array
    BPF_F_CURRENT_CPU, // Buffer associado ao núcleo atual
    &event,            // Estrutura para armazenar
    sizeof(event)      // Tamanho
);
```
