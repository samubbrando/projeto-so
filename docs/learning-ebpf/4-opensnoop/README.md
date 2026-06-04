# Introdução

O foco dessa seção é avaliar como o eBPF vai lidar com as variáveis globais, o caso de exemplo é para fazer análise de leituras de arquivos.

O aspecto interessante da prática explícita nessa seção é que estamos forçando o nosso sistema a toda vez visitar nossa variável ao definir ela como foi definida. Acredito que caia mais em um dilema de otimização do código C/compilador, mas é algo interessante porquê deixa explícito a necessidade disso.

Se chegar a gerar o programa, é bem interessante observar como isso é armazenado no pacote de execução (package.json):

```json
{
    "bpf_object":"...",
    "bpf_object_size":2936,
    "meta":{
        "bpf_skel":{
            "data_sections":[
                {
                    "name":".rodata",
                    "variables":[
                        {
                            "name":"target",
                            "type":"int"
                        }
                    ]
                }
            ],
            "maps":[
                {
                    "ident":"rodata",
                    "mmaped":true,
                    "name":"open_fil.rodata"
                }
            ],
            "obj_name":"open_file_bpf",
            "progs":[
                {
                    "attach":"tp/syscalls/sys_enter_openat",
                    "link":true,
                    "name":"trace_open_file"
                }
            ]
        },
    "eunomia_version":"0.3.4"
    }
}
```

Se o compilador precisar jogar em .data, ele não terá suporte dará esse erro ao acessar o package:

```log
samuel@suporte-Inspiron-15-3530:~/programas/projeto-so/docs/learning-ebpf/4-opensnoop$ sudo ecli package.json
INFO [faerie::elf] strtab: 0x495 symtab 0x4d0 relocs 0x518 sh_offset 0x518
Error: Failed to run native eBPF program

Caused by:
    Bpf error: Failed to start polling: Bpf("Failed to load and attach: Unsupported section: .data"), RecvError
```

##### Isso é interessante para o desenvolvimento do projeto.
> The annotation /// @description "Process ID to trace" above the global variable is special - eunomia-bpf uses it to automatically generate command-line help text. This makes your tool more user-friendly without extra code.

