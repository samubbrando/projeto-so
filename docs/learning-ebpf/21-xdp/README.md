# Introdução

XDP é um data path que permite que você atue sobre os pacotes de dados enquanto estão em CPU. Ou seja, você consegue atuar antes mesmo do kernel atuar sobre eles. Isso gera uma vantagem de velocidade e permite um controle muito maior do que o que é observado normalmente.

XDP não ocorre de forma completamente desanexada do kernel, mas sim associada com ele. Diferente da ideia do DPDK, a ideia é trabalhar ao lado do Kernel provendo os dados cabíveis antes de processamento, interceptando na placa de rede. 

Com a integração com eBPF, o sistema não vai ter problema de XDP pegar informações demais, até porque roda encapsulado no domínio da "VM" do eBPF.
