# Introdução

Esse material gira em torno de monitorar mudanças de estado das conexões TCP e monitoramento de tempo de cada estado, associando a fluxo de execução. Como, por exemplo, tempo passado em envio de dados.

## tcpstates

- `sock/inet_sock_set_state` -> Mudança de estado de qualquer conexão TCP.
    - Sobre isso: o ctx seria o `trace_event_raw_inet_sock_set_state`, possui atributos (family, sport, dport, protocol, skaddr)

- `bpf_ktime_get_ns()` -> Retorna o tempo desde o boot do sistema

- `inet_ntop` função de formatação: binário -> algo humanamente lível (str)

Importante aspecto que eu passei a me esquecer. Mas o código é separado em código enviado para o kernel (bpf.c) e o meu código (.c).

Eu acho que é interessante observar as distinções dos estados que eu consigo obter através das extensões oferecidas pelo ebpf.

## tcprtt

- `BPF_PROG`: macro de fentry
- `tcp_rcv_established`: serve para detectar recebimentos de pacotes em conexões do tipo "ESTABLISHED".