# Introdução 

Aqui a gente agora vai fazer a saída através do Ring Buffer.

Os problemas que o Ring Buffer resolveu foi para eficiência de memória e reordenação de entidades armazenadas no perfbuffer.

Isso aqui é o novo standard contemporâneo.

# Definição

Perf Buffer:
- Aqui vamos ter um buffer por CPU 
- Problemas de ordenação (é por ser por CPU, então vai ser dependendo de quanto for escalonado para a subida, não dá para manter uma ordem perfeita)
- Problemas de eficiência de memória (causado por ser um buffer por CPU, ou seja, cai nas mãos do escalonador o empilhamento, uma CPU pode ter um monte monte de processos e outra nada)

Ring Buffer:
- MPSC (Multiple Producer Single Consumer)
- Todas as CPUs enviam os dados enquanto somente um buffer vai agregar e consumir eles
- Pode ser seguramente compartilhado entre n CPUs
- Resolve os problemas citados no Perf Buffer

## Fluxo

Boa parte do fluxo, em quesito de código, não muda, o que muda mais é o fluxo para guardar dados no buffer.

1. Você aloca recurso para guardar seus dados
- `e = bpf_ringbuf_reserve(&ring_buffer, tamanho, flags)`
- flags indica o comportamento, 0 é o comportamento padrão

2. Você vai alterar o espaço enviado para você
- `e->atributo = dado`

3. Você submete os dados enviados
- `bpf_ringbuf_submit(e, flags)`
- 0 também é o padrão

Você também pode descartar caso algum passo do seu código dê errado:
`bpf_ringbuf_discard(e)`