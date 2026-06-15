# Introdução

Aqui ele mostra e execução de um programa que consegue se anexar a pontos específicos do TC. Isso pode ser MUITO útil para o projeto que eu estou montando.
Basicamente explica sobre como funciona o fluxo do TC, com os qdiscs e detalhes de implementação geral na introdução.

O fluxo relatadao: 
- Pacote chega ao qdisc do topo;
- Interface de enqueue;
- Filtros são aplicados um a um até haver um match de classe;
- Ao haver um match -> Envia para a classe especificada.

#### Mecanismo Classifier-Action

Ao haver um filtro, temos geralmente um classifier para uma ação a ser tomada. O filtro associado separa os pacotes adequados de serem aplicados a dada ação.
Por isso, classifier-action -> Classifica e atua sobre o pacote de forma "simultânea".

## Fluxo do TC 

O eBPF pode atuar de forma direta em qdiscs especificados por meio de ações já implementadas para os programas eBPF. O programa em si tem ações equivalentes permitidas pelo TC que permitem que o programa em kernel atue retornando esses sinais.

### Uso de ///

Coementários especializados do TC, a documentação deles está [aqui](https://patchwork.kernel.org/project/netdevbpf/patch/20210512103451.989420-3-memxor@gmail.com/). O que vai definir a que função vamos attachar nosso script é esse tipo de comentário.

## Operação

- O resultado do contexto de atuação (*ctx) é um `__sk_buff`.
- Vc consegue saber onde está oinício e o fim do pacote que foi enviado:
```c
void *data_end = (void *)(__u64)ctx->data_end;
void *data = (void *)(__u64)ctx->data;
```

- Verificação de protocolo, se for IPv4 com Big Endian (host -> network byte order) (`bpf_htons(ETH_P_IP)`):
```c
if (ctx->protocol != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;
```

- Verificação das limitações para ler o pacote (note que o kernel pode rejeitar qualquer código minimamente suspeito de crashar, então isso é util para evitar esse aspecto)
```c
l2 = data;
if ((void *)(l2 + 1) > data_end) // Se o fim do pacote na memória passar do limite do final dele na memória
    return TC_ACT_OK;
```
- Mesma ideia para a verificação do IP.
```c
l3 = (struct iphdr *)(l2 + 1);
if ((void *)(l3 + 1) > data_end)
    return TC_ACT_OK;
```

