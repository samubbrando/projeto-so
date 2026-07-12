#ifndef NETLINK_FUNCS_H
#define NETLINK_FUNCS_H

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

#define MAX_PROCCESSES 32768 
#define MAX_NAME_SIZE 512
#define MAX_SOCKETS 8192

typedef struct socket_proccess {
    int socket_inode;
    char name[MAX_NAME_SIZE];
    char pid[16];
    char src_ip[INET_ADDRSTRLEN];
    int src_port;
    char end_ip[INET_ADDRSTRLEN];
    int end_port;
    unsigned long long tx_bytes;
    unsigned long long rx_bytes;
    unsigned int rtt;
} socket_proccess_t;

typedef struct proc_agg {
    char pid[16];
    char name[MAX_NAME_SIZE];
    unsigned long long tx_bytes;
    unsigned long long rx_bytes;
    int socket_count;
} proc_agg_t;

void find_pids_for_inode(ino_t target_inode, socket_proccess_t *sockets_list, int current_index) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return;

    struct dirent *proc_entry;

    while ((proc_entry = readdir(proc_dir)) != NULL) {
        if (proc_entry->d_name[0] < '0' || proc_entry->d_name[0] > '9') continue;
        
        char fd_path[265];
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", proc_entry->d_name);
        
        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;
        
        int found = 0;
        struct dirent *fd_entry;

        while ((fd_entry = readdir(fd_dir)) != NULL) {
            struct stat st;
            char link_path[521];
            
            snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_entry->d_name);
            
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

            snprintf(path, sizeof(path), "/proc/%s/comm", proc_entry->d_name);
            FILE *comm = fopen(path, "r"); 

            if (comm != NULL) { 
                if (fgets(name, sizeof(name), comm)) {
                    name[strcspn(name, "\n")] = '\0';
                    strncpy(sockets_list[current_index].name, name, sizeof(sockets_list[current_index].name) - 1);
                    sockets_list[current_index].name[sizeof(sockets_list[current_index].name) - 1] = '\0';
                }
                fclose(comm);
            }
        }
        closedir(fd_dir);
    }
    closedir(proc_dir);
}

char* detect_default_iface(void) {
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) {
        perror("Failure opening /proc/net/route");
        return NULL;
    }

    char line[256];
    char iface[32];

    while (fgets(line, sizeof(line), fp)) {
        unsigned long dest, mask;
        if (sscanf(line, "%31s %lx %*s %*s %*s %*s %*s %lx", iface, &dest, &mask) == 3) {
            if (dest == 0 && mask == 0) {
                fclose(fp);
                char *result = (char *) malloc(strlen(iface) + 1);
                if (result) {
                    strcpy(result, iface);
                }
                return result;
            }
        }
    }

    fclose(fp);
    return NULL;
}

int discover_sockets(socket_proccess_t *sockets_captured) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
    int total_sockets_found = 0;

    if (sock < 0) {
        perror("Falhou ao criar o socket");
        return 1;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Erro no bind");
        close(sock);
        return 1;
    }

    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } request;

    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = sizeof(request);
    request.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; 

    request.req.idiag_states = ~0;
    request.req.sdiag_family = AF_INET;
    request.req.sdiag_protocol = IPPROTO_TCP;

    struct sockaddr_nl kernel = {0};
    kernel.nl_family = AF_NETLINK;

    sendto(sock, &request, sizeof(request), 0, (struct sockaddr *)&kernel, sizeof(kernel));
    
    char buffer[8192];
    int len = recv(sock, buffer, sizeof(buffer), 0);

    struct nlmsghdr *nlh;

    for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            printf("Erro na mensagem Netlink\n");
            break;
        }

        struct inet_diag_msg *diag = (struct inet_diag_msg *) NLMSG_DATA(nlh);
        
        char src[INET_ADDRSTRLEN];
        char dst[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, diag->id.idiag_src, src, sizeof(src));
        inet_ntop(AF_INET, diag->id.idiag_dst, dst, sizeof(dst));

        int sport = ntohs(diag->id.idiag_sport);
        int dport = ntohs(diag->id.idiag_dport);
        
        memset(&sockets_captured[total_sockets_found], 0, sizeof(socket_proccess_t));
        
        strncpy(sockets_captured[total_sockets_found].src_ip, src, INET_ADDRSTRLEN);
        sockets_captured[total_sockets_found].src_port = sport;
        strncpy(sockets_captured[total_sockets_found].end_ip, dst, INET_ADDRSTRLEN);
        sockets_captured[total_sockets_found].end_port = dport;

        find_pids_for_inode(diag->idiag_inode, sockets_captured, total_sockets_found);
        total_sockets_found++;
    }
    
    close(sock);
    return total_sockets_found;
}

#endif
