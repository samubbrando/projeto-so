# Introdução

Kprobes é basicamente uma maneira de garantir, sem necessidade de reset do sistema operacional, o fluxo das variáveis definidas no escopo do código do kernel de serem avaliadas.
Isso é útil para debugging rápido.

Fluxo:
```
Probe -> Funcao

CPU -> F(L1) -> F(L2) -> Probe -> Função de callback -> F(L4) -> ...
```

## Métodos de detecção

- Kprobe > BPF_KPROBE:
    - Pre-Handler, Post_Handler e Fault_Handler
        - Pre e Post são relacionados a chamar antes de iniciar e depois de finalizar a função
        - Fault é para indicar problemas de acesso a memória
- Jprobe:
    - Baseado no kprobe
    - Obtém PARAMETROS da função 
- Kretprobe > BPF_KRETPROBE:
    - Obtém dados de retornos da função

