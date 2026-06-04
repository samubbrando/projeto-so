# Instalações iniciais

- Ferramenta de ecli para rodar os scripts ebpf: para rodar é só executar o arquivo `ecli`

```bash
wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
```

- Ferramentas de compilação dos códigos ecc: para rodar é só executar o arquivo `ecc`

```bash
wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
```

- Compilador geral para buildar os objetos
```bash
sudo apt install clang llvm
```

# Para rodar

```bash
./ecc codigo.bpf.c # No caso eu fiz hello.bpf.c
sudo ./ecli run package.json
```

Para observar os logs, você pode ler eles através disso:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "Mensagem do seu printk"
```

É interessante fazer esse grep porque esse recurso é para todo o sistema, então vão ter vários logs que você pode não querer ver sobre.

# Utilitários úteis desse material

- `sudo ls /sys/kernel/debug/tracing/events/syscalls/` me passa todos os tracepoints do meu SO

- 