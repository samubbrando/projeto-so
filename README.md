# projeto-so

O objetivo deste projeto é desenvolver um sistema capaz de controlar e distribuir recursos de rede entre processos em execução em um sistema Linux.
O sistema deverá executar em segundo plano como um daemon, monitorando continuamente os processos ativos, identificando quais deles utilizam recursos de rede e aplicando políticas de limitação ou expansão de banda conforme regras previamente definidas.
A proposta é permitir que determinados executáveis previamente autorizados possam utilizar a largura de banda disponível de forma controlada, garantindo maior previsibilidade no uso dos recursos de rede do sistema.
As principais aplicações para esse sistema são como uma proteção extra para sistemas que se dedicam apenas para funcionamento de certos processos, pois poderia permitir um controle de rede único e reservado apenas para os processos separados.


## Documentação

O código documentado até que demais está na pasta `docs`, eu fiz assim porque ficava pouco claro algumas coisas e queria que fizesse sentido, alguns comentários não estão muito verbalmente belos, mas é uma explicação simplificada do porque cada coisa foi feita que fizesse sentido.

## Desenvolvimento

Aqui vou documentar as etapas de forma resumida e objetiva para indicar como tem sido tomada cada decisão relativa a esse projeto.

### Início
Primeiramente, a frente foi seguida utilizando estudos de conexão básicos, foi utilizado a documentação de sockets para primeiramente entender sobre como funciona conexões básicas.

A partir disso, eu migrei para o estudo do fluxo de conexão socket na linguagem C, isso foi feito por meio da [documentação](https://man7.org/linux/man-pages/man7/netlink.7.html) do linux para sockets netlink.

Dessa parte, foi escrito o escopo inicial do código, que visava apenas ver as conexões IP que eram selecionadas para cada socket netlink.

Após isso, foi desenvolvido utilitários para identificação melhor dos sockets, propriedades gerais deles, como as filas, separação da fonte para o destino, qual inode era associado. Nessa fase foi feito um melhor estudo dos sockets, representação deles nos sistemas e fluxos de redes para entender melhor as operações possibilitadas pelas ferramentas oferecidas.

Por último, nessa fase inicial foi desenvolvida a utilidade de identificação dos processos em si, primeiro como um print, depois foi desenvolvido um sistema para agregar cada processo em uma estrutura apropriada para identificação futura em código.

### Identificação de possibilidades

Diversas possibilidades foram encontradas, trabalhar com wrapper para traffic control foi a principal delas, mas soluções com eBPF aparentavam uma capacidade de escala muito maior.

#### Estudo do eBPF

Utilizando da documentação disponibilizada no site principal relativo ao sistema do eBPF, [ebpf.io](https://ebpf.io/), foi selecionado o repositório: [eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial/) para aprendizado das etapas.

Além disso, entender o que o sistema almejava alcançar por meio do [documentário](https://www.youtube.com/watch?v=Wb_vD3XZYOA) do desenvolvimento do sistema do eBPF, além de estudos para entendimento mais aprofundado do fluxo de rede no kernel, esse foi um dos principais [vídeos](https://www.youtube.com/watch?v=ck4WvYM9V4c) do tópico.