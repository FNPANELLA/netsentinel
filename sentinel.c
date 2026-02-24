#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>

typedef struct {
    char ip[16];
    int count;
    time_t start_time;
} IPTracker;

#define MAX_TRACKED_IPS 100
#define ALERT_THRESHOLD 50

IPTracker trackers[MAX_TRACKED_IPS];

// Estructura espejo
typedef struct {
    char source_ip[16];
    char dest_ip[16];
    int src_port;
    int dst_port;
    int protocol;
    int size;
    int is_alert;
} PacketInfo;

int sock_raw = -1;

int init_sniffer() {
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) return -1;

    memset(trackers, 0, sizeof(trackers));
    return 0;
}

int check_traffic_spike(const char* src_ip) {
    time_t now = time(NULL);
    int empty_slot = -1;

    //search ip on booklet
    for (int i = 0; i < MAX_TRACKED_IPS; i++) {
        if (trackers[i].ip[0] == '\0' && empty_slot == -1) {
            empty_slot = i; // saving 1 for latest empty slot
        } else if (strcmp(trackers[i].ip, src_ip) == 0) {
            // ip jot down
            if (now - trackers[i].start_time > 1) {
                // +1 sec counter restarts
                trackers[i].count = 1;
                trackers[i].start_time = now;
                return 0; 
            } else {
                // same sec, count ++
                trackers[i].count++;
                if (trackers[i].count > ALERT_THRESHOLD) {
                    return 1; // blyat, over 50 
                }
                return 0; // ++ but no overlimit
            }
        }
    }

    // if ip not in booklet, jot it
    if (empty_slot != -1) {
        strncpy(trackers[empty_slot].ip, src_ip, 15);
        trackers[empty_slot].count = 1;
        trackers[empty_slot].start_time = now;
    }
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

        
    }if (strcmp(info->source_ip, "127.0.0.1") != 0) {
        info->is_alert = check_traffic_spike(info->source_ip);
    } else {
        info->is_alert = 0;
    }
    return 0;
}