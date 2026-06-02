# projeto-so

O objetivo deste projeto é desenvolver um sistema capaz de controlar e distribuir recursos de rede entre processos em execução em um sistema Linux.
O sistema deverá executar em segundo plano como um daemon, monitorando continuamente os processos ativos, identificando quais deles utilizam recursos de rede e aplicando políticas de limitação ou expansão de banda conforme regras previamente definidas.
A proposta é permitir que determinados executáveis previamente autorizados possam utilizar a largura de banda disponível de forma controlada, garantindo maior previsibilidade no uso dos recursos de rede do sistema.
As principais aplicações para esse sistema são como uma proteção extra para sistemas que se dedicam apenas para funcionamento de certos processos, pois poderia permitir um controle de rede único e reservado apenas para os processos separados.


## Documentação

O código documentado até que demais está na pasta `docs`, eu fiz assim porque ficava pouco claro algumas coisas e queria que fizesse sentido, alguns comentários não estão muito verbalmente belos, mas é uma explicação simplificada do porque cada coisa foi feita que fizesse sentido.
