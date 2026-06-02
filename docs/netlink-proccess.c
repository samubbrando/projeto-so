#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/stat.h>

// Valor padrão, Sistemas Linux modernos podem suportar 4.194.304 
// proccessos, mas trabalhei com o padrão
#define MAX_PROCCESSES 32768 

#define MAX_NAME_SIZE 512

// Esse valor não tem limite, só escolhi um valor para trabalhar
// Como cada socket ocupa 8KB de RAM, poderia na minha máquina caber
// até 2^21 sockets (16GB de RAM), mas isso é um absurdo para o 
// escopo da aplicação e com 100% de certeza faria meu notebook travar.
#define MAX_SOCKETS 8192 // 2 ^ 13

typedef struct socket_proccess {
    int socket_inode;
    char name[MAX_NAME_SIZE];
    char pid[16];
    char src_ip[INET_ADDRSTRLEN];
    int src_port;
    char end_ip[INET_ADDRSTRLEN];
    int end_port;
} socket_proccess_t;

void find_pids_for_inode(ino_t target_inode, socket_proccess_t *sockets_list, int current_index) {
    /*
     * A ideia desse método é listar todos os diretórios relativos a PIDs em /proc
     * e depois acessar fd para determinar a qual inode esses objetos estariam 
     * relacionados. Se for relacionado ao inode alvo, é relacionado ao socket que
     * está sendo analisado.
     *
     * target_inode: inode do socket para ser analisado.
     * sockets_list: lista de sockets onde vou armazenar o processo que achei associado.
     * current_index: indice atual da lista para atualizar
     */ 

    DIR *proc_dir;
    struct dirent *proc_entry;

    proc_dir = opendir("/proc");

    // Lendo /proc por inteiro
    while ((proc_entry = readdir(proc_dir)) != NULL) {
        // Verifica se é um diretório com nome numérico (se for pode ser PID)
        if (proc_entry->d_name[0] < '0' || proc_entry->d_name[0] > '9') continue;
        
        // String com o path para analisar
        char fd_path[265]; // Limite que o compilador mandou eu botar
        snprintf(
            fd_path,            // Variável de destino 
            sizeof(fd_path),    // Tamanho do buffer de destino
            "/proc/%s/fd",      // A. A formatação da string que vai ser posta lá
            proc_entry->d_name  // B. O que eu vou formatar para a string
        );                      // Coloquei esses dois como A e B porque são relacionados diretamente
        
        // Abre o diretório relativo ao PID
        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;
        

        int found = 0;
        struct dirent *fd_entry;
        // Lê o diretório do processo inteiramente
        while ((fd_entry = readdir(fd_dir)) != NULL) {
            struct stat st;

            char link_path[521]; // Limite que o compilador demandou
            snprintf(
                link_path, 
                sizeof(link_path), 
                "%s/%s",
                fd_path, 
                fd_entry->d_name
            );
            
            // Stat lê os metadados do arquivo no descriptor e armazena os resultados em st:
            // Se for sucesso -> 0;
            // Se o inode nas estatísticas for o que mandamos, esse PID é relacionado ao inode.
            
            if (stat(link_path, &st) == 0 && st.st_ino == target_inode) {
                sockets_list[current_index].socket_inode = target_inode;
                strncpy(sockets_list[current_index].pid, proc_entry->d_name, sizeof(sockets_list[current_index].pid) - 1);
                
                found = 1;
                break;             
            }
        }
        
        if (found == 1) {
            char path[267];
            char name[256];

            snprintf(
                path,
                sizeof(path),
                "/proc/%s/comm",   // Contém o nome do executável
                proc_entry->d_name
            );

            FILE *comm = fopen(path, "r"); 

            if (comm != NULL) { 
                if (fgets(name, sizeof(name), comm)) { // Se a leitura for um sucesso, ele continua, evita lixo
                    name[strcspn(name, "\n")] = '\0';
                    strncpy(sockets_list[current_index].name, name, sizeof(sockets_list[current_index].name) - 1);
                    sockets_list[current_index].name[sizeof(sockets_list[current_index].name) - 1] = '\0';
                }
            } else {
                printf(" - Proccess: Not found\n");
            }
            
            fclose(comm);
        }

        closedir(fd_dir);
    }
    closedir(proc_dir);
}

int main() {

    // Onde vamos armazenar nossos sockets capturados com processos
    socket_proccess_t *sockets_captured = malloc(sizeof(socket_proccess_t) * MAX_SOCKETS);
    if (sockets_captured == NULL) {
        perror("Erro ao alocar memória para os sockets");
        return 1;
    }    

    int total_sockets_found = 0;

    // Cria um socket comunicando através desse cara aí
    // Isso deve dar um id válido, se for < 0, falhou
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);

    if (sock < 0) {
        printf("Falhou ao criar o socket");
        return 1;
    }

    struct sockaddr_nl addr;
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();

    bind(
        sock, // Socket 
        (struct sockaddr *)&addr, // Fazemos um cast para uma estrutura endereco do tipo sockaddr;
                                  // Feito isso, retornamos o endereco do objeto;  
        sizeof(addr) // Tamanho do endereco
    );


    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } request;

    /*
    struct nlmsghdr {
        __u32 nlmsg_len;    // Size of message including header 
        __u16 nlmsg_type;   // Type of message content 
        __u16 nlmsg_flags;  // Additional flags 
        __u32 nlmsg_seq;    // Sequence number 
        __u32 nlmsg_pid;    // Sender port ID 
    };
    */

    request.nlh.nlmsg_len = sizeof(request); // Mensagem (req) + header (nlh)
    request.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY; // Informacões do dsocket pela família (iPv4, iPv6)
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; 
    /*
    NLM_F_REQUEST: Aplica para todas as mensagens enviadas;
    NLM_F_DUMP: Faz o efeito de duas flags, retorna a tabela toda e todas as 
        entries que deram match na query
    */

    request.req.idiag_states = ~0;
    request.req.sdiag_family = AF_INET;
    request.req.sdiag_protocol = IPPROTO_TCP;

    struct sockaddr_nl kernel = {0};
    kernel.nl_family = AF_NETLINK;

    sendto(
        sock,
        &request,
        sizeof(request),
        0,
        (struct sockaddr *)&kernel,
        sizeof(kernel)
    );
    
    char buffer[8192];
    int len = recv(sock, buffer, sizeof(buffer), 0);

    struct nlmsghdr *nlh;

    for (nlh = (struct nlmsghdr *)buffer;
        NLMSG_OK(nlh, len);
        nlh = NLMSG_NEXT(nlh, len)) {

        if (nlh->nlmsg_type == NLMSG_DONE)
            break;

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            printf("Erro\n");
            break;
        }
        /*
         * struct inet_diag_msg {
                   __u8 	idiag_family
                   __u8 	idiag_state
                   __u8 	idiag_timer
                   __u8 	idiag_retrans
struct inet_diag_sockid 	id
                   __u32 	idiag_expires
                   __u32 	idiag_rqueue
                   __u32 	idiag_wqueue
                   __u32 	idiag_uid
                   __u32 	idiag_inode
         *  }
         */

        struct inet_diag_msg *diag =
            (struct inet_diag_msg *) NLMSG_DATA(nlh);
        

        /*
         * struct inet_diag_sockid {
               __be16  idiag_sport;
               __be16  idiag_dport;
               __be32  idiag_src[4];
               __be32  idiag_dst[4];
               __u32   idiag_if;
               __u32   idiag_cookie[2];
           };
         */
        char src[INET_ADDRSTRLEN];
        char dst[INET_ADDRSTRLEN];

        // Converter IP binário -> string
        inet_ntop(AF_INET, diag->id.idiag_src, src, sizeof(src));
        inet_ntop(AF_INET, diag->id.idiag_dst, dst, sizeof(dst));

        // Portas (precisa converter de network byte order)
        int sport = ntohs(diag->id.idiag_sport);
        int dport = ntohs(diag->id.idiag_dport);
        
        unsigned int rqueue = diag->idiag_rqueue;
        unsigned int wqueue = diag->idiag_wqueue;
        
        memset(&sockets_captured[total_sockets_found], 0, sizeof(socket_proccess_t));
        
        strncpy(sockets_captured[total_sockets_found].src_ip, src, INET_ADDRSTRLEN);
        sockets_captured[total_sockets_found].src_port = sport;
        strncpy(sockets_captured[total_sockets_found].end_ip, dst, INET_ADDRSTRLEN);
        sockets_captured[total_sockets_found].end_port = dport;

        find_pids_for_inode(diag->idiag_inode, sockets_captured, total_sockets_found);
        total_sockets_found++;

        /* Não há proteção para overflow da quantidade de processos 
         * porque é interessante para mim ver se a quantidade selecionada
         * foi bastante.
         * O código para isso poderia ser:
         * if (total_sockets_found >= MAX_SOCKETS) break;
         */
    }

    for (int i = 0; i < total_sockets_found; i++) {
        socket_proccess_t socket = sockets_captured[i];
        
        // typedef struct socket_proccess {
        //     int socket_inode;
        //     char name[MAX_NAME_SIZE];
        //     char pid[16];
        //     char src_ip[INET_ADDRSTRLEN];
        //     int src_port;
        //     char end_ip[INET_ADDRSTRLEN];
        //     int end_port;
        // } socket_proccess_t;
        
        if (socket.pid[0] != '\0') {
            printf("=================================\n");
            printf("(SRC)\n  IP: %s\n  Port: %d", socket.src_ip, socket.src_port);
            printf("\n(DESTINATION)\n  IP: %s\n  PORT: %d\n", socket.end_ip, socket.end_port);
            printf("\nINODE: %d\n", socket.socket_inode);
            printf("\n(PROCESS):\n  PID: %s\n  NAME: %s\n", socket.pid, socket.name);
        }
    }

    close(sock);
    free(sockets_captured);
    return 0;
}