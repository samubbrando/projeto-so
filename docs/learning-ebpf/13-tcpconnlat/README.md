# Introdução

O problema que essa seção analisa é o tempo de conexão TCP através da ferramenta `tcpconnlat`.

### Fluxo 

1. Cliente envia pacote SYN para o server. Através de syscall `connect`. (CPU para interrupção)
2. SYN é transmitido pro server, depende da latência. (Rede)
3. Server lida com o pacote SYN, o kernel recebe por uma interrupção (CPU para interrupção de novo) e põe o server em modo de escuta e envia sinais de SYN e de ACK para o client (CPU para interrupção)
4. SYN/ACK é transmitido pro cliente (Rede)
5. Clinte lida com o SYN/ACK e manda ACK de volta, baseado na interrupção causada pelos sinais (CPU para interrupção)
6. ACK é transmitido para o servidor (Rede)
7. Servidor recebe ACK e fica em queue recebendo os sinais enviados na interface especificada.
8. O processo do lado do servidor acorda para fazer um `accept`


No kernel:
1. Valida parâmetros
2. Determina destino e nexthop
3. Procura uma rota válida
4. Escolhe endereço de origem
5. Configura estado interno do socket TCP
6. Reserva a tupla (src_ip, src_port, dst_ip, dst_port)
7. Cria/atualiza o cache de rota
8. Prepara números de sequência
9. Tenta TCP Fast Open
10. Caso contrário, envia SYN normal

### Fluxo eBPF

1. Listen Queue: Fila do que vai ser ouvido ainda, no processo do handshake
2. Established Queue: Após estabelecer, todas as conexões em andamento ficam nessa fila

### Funções

Inicializar conexões:
- `tcp_v4_connect` -> `trace_connect(sk)`
- `tcp_v6_connect` -> `trace_connect(sk)`

Quando o estado da conexão muda
- `tcp_rcv_state_process` -> `handle_tcp_rcv_state_process(ctx, sk)`

O probe delas segue a estrutura:
(nome_func, struct sock *socket)

## Análise

Aqui eu vou tentar resumir a explicação do fluxo definido no repositório.


1. Source Routing

Essa parte aqui é interessante porque setta para caso de Source Routing. Serve para permitir que quem está enviando decida previamente a rota pela qual irá enviar o pacote. A gente pode especificar o caminho que o pacote vai tomar para o trajeto ao invés de demandar do sistema de roteamento normal.

```c
nexthop = daddr = usin->sin_addr.s_addr;

inet_opt = rcu_dereference_protected(
    inet->inet_opt,
    lockdep_sock_is_held(sk)
);

if (inet_opt && inet_opt->opt.srr) { // Existe Source Routing configurado
    if (!daddr)
        return -EINVAL; // Source Routing só faz sentido se houver um destino final válido 

    nexthop = inet_opt->opt.faddr; // O roteamento vai ser calculado para cá primeiro
                                   // para o cálculo da rota inicial.
}                                  
```

A ideia é tipo:
- Com Source Routing: `route_analysis(first_addr)`
- Sem Source Routing: `route_analysis(destination_addr)`

Se não puder ter uma rota para o ponto de destino -> erro.
Se o destino for multicast ou broadcast -> erro.

2. Busca de rota

Chamada `ip_route_connect()`, procura se existe rota para o endereço indicado. Se existir, antes verifica se é broadcast ou multicast.
Se não tiver rota, ou for uma rota para endereço broadcast/multicast ele retorna uma exceção.

3. Escolha

Rota informada retorna a fonte, a interface e o destino. Tipo:
```
Interface: eth0
IP local: 192.168.1.10
Gateway: 192.168.1.1
```

Aí o kernel pega os parâmetros daí (saddr, daddr, etc) e coloca no socket.

O socket vai para a fila de sockets funcionando. Sai de CLOSED -> TCP_SYN_SENT. 
E é usado a função para hashar esse socket para os ativos (`inet_hash_connect`). Atribui a conexão a uma porta valida.

E segura a sequência: `secure_tcp_seq` para garantir o SYN especializado para ele. Assim ele identifica quem mandou ou enviou dados.

5. TCP Fast Open
Aqui se estiver habilitado ele manda dados de forma simultânea ao SYN. Precisa ser habilitado do lado do receptor e do emissor.

Se não: 
- Client: SYN 
- Server: SYN-ACK
- Client: ACK
- Client: DATA 

## Avaliando tcpconnlat

1. O programa monitora tentativas de conexão TCP usando probes em `tcp_v4_connect()` e `tcp_v6_connect()`.

2. Quando um processo chama `connect()`, ele registra em um mapa:
   - o socket (`struct sock *`);
   - o PID/TGID;
   - o nome do processo;
   - o timestamp de início da conexão.

3. O programa acompanha eventos em `tcp_rcv_state_process()`, executado durante o processamento de pacotes TCP recebidos.

4. Quando encontra um socket previamente registrado em estado `TCP_SYN_SENT`, ele calcula o tempo decorrido desde o `connect()`.

5. Essa diferença de tempo representa uma estimativa da latência de estabelecimento da conexão TCP (handshake).

6. O programa coleta informações adicionais do socket, como:
   - endereços IP de origem e destino;
   - portas de origem e destino;
   - PID do processo;
   - nome do executável.

7. Os dados coletados são enviados para o espaço de usuário através de um mapa `BPF_PERF_EVENT_ARRAY`.

8. Após gerar o evento, o registro do socket é removido do mapa para evitar medições duplicadas.

9. Ele mede apenas a latência de criação da conexão TCP.
