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

typedef struct socket_proccess
{
    int socket_inode;
    char name[MAX_NAME_SIZE];
    char pid[16];
    char src_ip[INET6_ADDRSTRLEN];
    int src_port;
    char end_ip[INET6_ADDRSTRLEN];
    int end_port;
    unsigned long long tx_bytes;
    unsigned long long rx_bytes;
    unsigned int rtt;
    int protocol;
    int family;
} socket_proccess_t;

typedef struct proc_agg
{
    char pid[16];
    char name[MAX_NAME_SIZE];
    unsigned long long tx_bytes;
    unsigned long long rx_bytes;
    int socket_count;
} proc_agg_t;

void find_pids_for_inode(ino_t target_inode, socket_proccess_t *sockets_list, int current_index)
{
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir)
        return;

    struct dirent *proc_entry;

    while ((proc_entry = readdir(proc_dir)) != NULL)
    {
        if (proc_entry->d_name[0] < '0' || proc_entry->d_name[0] > '9')
            continue;

        char fd_path[265];
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", proc_entry->d_name);

        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir)
            continue;

        int found = 0;
        struct dirent *fd_entry;

        while ((fd_entry = readdir(fd_dir)) != NULL)
        {
            struct stat st;
            char link_path[521];

            snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_entry->d_name);

            if (stat(link_path, &st) == 0 && st.st_ino == target_inode)
            {
                sockets_list[current_index].socket_inode = target_inode;
                strncpy(sockets_list[current_index].pid, proc_entry->d_name, sizeof(sockets_list[current_index].pid) - 1);
                found = 1;
                break;
            }
        }

        if (found == 1)
        {
            char path[267];
            char name[256];

            snprintf(path, sizeof(path), "/proc/%s/comm", proc_entry->d_name);
            FILE *comm = fopen(path, "r");

            if (comm != NULL)
            {
                if (fgets(name, sizeof(name), comm))
                {
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

char *detect_default_iface(void)
{
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp)
    {
        perror("Failure opening /proc/net/route");
        return NULL;
    }

    char line[256];
    char iface[32];

    while (fgets(line, sizeof(line), fp))
    {
        unsigned long dest, mask;
        if (sscanf(line, "%31s %lx %*s %*s %*s %*s %*s %lx", iface, &dest, &mask) == 3)
        {
            if (dest == 0 && mask == 0)
            {
                fclose(fp);
                char *result = (char *)malloc(strlen(iface) + 1);
                if (result)
                {
                    strcpy(result, iface);
                }
                return result;
            }
        }
    }

    fclose(fp);
    return NULL;
}

int discover_sockets(socket_proccess_t *sockets_captured, int protocol, int family, int *total_sockets_found) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);

    if (sock < 0)
    {
        perror("Falhou ao criar o socket");
        return 1;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Erro no bind");
        close(sock);
        return 1;
    }

    struct
    {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } request;

    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = sizeof(request);
    request.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

    request.req.idiag_states = ~0;
    request.req.sdiag_family = family;
    request.req.sdiag_protocol = protocol;

    struct sockaddr_nl kernel = {0};
    kernel.nl_family = AF_NETLINK;

    if (sendto(sock, &request, sizeof(request), 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
        perror("sendto");
        close(sock);
        return 1;
    }

    char buffer[65536];
    int len = 0;

    while (1) {
        int ret = recv(sock, buffer + len, sizeof(buffer) - len, 0);
        if (ret < 0) { perror("recv"); break; }
        if (ret == 0) break;
        len += ret;

        struct nlmsghdr *last = (struct nlmsghdr *)buffer;
        int rem = len;
        while (NLMSG_OK(last, rem)) {
            if (last->nlmsg_type == NLMSG_DONE) goto parse;
            last = NLMSG_NEXT(last, rem);
        }
        if (len >= (int)sizeof(buffer)) break;
    }

parse:
    struct nlmsghdr *nlh;
    int remaining = len;
    int sa_family = (family == AF_INET6) ? AF_INET6 : AF_INET;

    for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            printf("Erro na mensagem Netlink\n");
            break;
        }

        struct inet_diag_msg *diag = (struct inet_diag_msg *)NLMSG_DATA(nlh);

        char src[INET6_ADDRSTRLEN];
        char dst[INET6_ADDRSTRLEN];

        inet_ntop(sa_family, diag->id.idiag_src, src, sizeof(src));
        inet_ntop(sa_family, diag->id.idiag_dst, dst, sizeof(dst));

        int sport = ntohs(diag->id.idiag_sport);
        int dport = ntohs(diag->id.idiag_dport);

        memset(&sockets_captured[*total_sockets_found], 0, sizeof(socket_proccess_t));

        strncpy(sockets_captured[*total_sockets_found].src_ip, src, INET6_ADDRSTRLEN);
        sockets_captured[*total_sockets_found].src_port = sport;
        strncpy(sockets_captured[*total_sockets_found].end_ip, dst, INET6_ADDRSTRLEN);
        sockets_captured[*total_sockets_found].end_port = dport;
        sockets_captured[*total_sockets_found].protocol = protocol;
        sockets_captured[*total_sockets_found].family = sa_family;

        find_pids_for_inode(diag->idiag_inode, sockets_captured, *total_sockets_found);
        (*total_sockets_found)++;
    }

    close(sock);
    return 0;
}

#endif
