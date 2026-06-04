# Introdução

Meio que uma maneira de observar a entrada e saída das funções de forma mais eficiente que o kprobe.
Você diretamente acessa os parâmetros passados ao invés de precisar de `BPF_CORE_READ`.

## Uso

Aqui a maneira de usar é sempre alocando para um macro `BPF_PROG`.

O Fentry e Fexit são probes com capacidade de atuar sobre os parâmetros recebidos/enviados de forma direta