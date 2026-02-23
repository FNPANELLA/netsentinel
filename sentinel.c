#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Estructura espejo
typedef struct {
    char source_ip[16];
    char dest_ip[16];
    int src_port;
    int dst_port;
    int protocol;
    int size;
} PacketInfo;

int sock_raw = -1;

int init_sniffer() {
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) return -1;
    return 0;
}

int get_packet(PacketInfo *info) {
    if (sock_raw < 0) return -2;

    unsigned char buffer[65536];
    struct sockaddr saddr;
    socklen_t saddr_size = sizeof(saddr);

    memset(buffer, 0, 65536);
    int data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);
    if (data_size < 0) return -1;

    memset(info, 0, sizeof(PacketInfo));

    struct iphdr *iph = (struct iphdr *)buffer;

    struct in_addr src, dst;
    src.s_addr = iph->saddr;
    dst.s_addr = iph->daddr;

    inet_ntop(AF_INET, &src, info->source_ip, 16);
    inet_ntop(AF_INET, &dst, info->dest_ip, 16);
    info->protocol = iph->protocol;
    info->size = data_size;

    unsigned short iphdrlen = iph->ihl * 4;

    if (iph->protocol == 6) {

        struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);

        info->src_port = ntohs(tcph->source);
        info->dst_port = ntohs(tcph->dest);
    } else {
        info->src_port = 0;
        info->dst_port = 0;
    }

    return 0;
}