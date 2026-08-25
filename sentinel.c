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
#include <linux/if_ether.h> 
#include <netinet/udp.h>
#include <pthread.h>


#define HASH_TABLE_SIZE 4096 
#define ALERT_THRESHOLD 1000


typedef struct {
    char ip[16];
    int count;
    time_t start_time;
    int active; // flag para saber si el slot está ocupado
} IPTracker;

IPTracker hash_table[HASH_TABLE_SIZE];

// typedef struct {
//    char ip[16];
  //  int count;
  //  time_t start_time;
// } IPTracker;



// Estructura espejo para Python
typedef struct {
    char source_ip[16];
    char dest_ip[16];
    int src_port;
    int dst_port;
    int protocol;
    int size;
    int is_alert;
} PacketInfo;

unsigned long hash_ip(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash % HASH_TABLE_SIZE;
}

int sock_raw = -1;
static pthread_mutex_t tracker_mutex = PTHREAD_MUTEX_INITIALIZER;

int init_sniffer() {
    sock_raw = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    if (sock_raw < 0) return -1;

    // Limpiamos la tabla hash completa al iniciar
    memset(hash_table, 0, sizeof(hash_table)); 
    return 0;
}

int check_traffic_spike(const char* src_ip) {
    time_t now = time(NULL);
    unsigned long index = hash_ip(src_ip);
    unsigned long start_index = index;

    //  Linear Probing
    while (hash_table[index].active) {
        
        // 1. Caso de éxito: Encontramos la IP (O(1))
        if (strcmp(hash_table[index].ip, src_ip) == 0) {
            if (now - hash_table[index].start_time > 1) {
                // Pasó el segundo de gracia, reseteamos
                hash_table[index].count = 1;
                hash_table[index].start_time = now;
                return 0; 
            } else {
                // Sigue en el mismo segundo
                hash_table[index].count++;
                if (hash_table[index].count > ALERT_THRESHOLD) {
                    return 1; // 
                }
                return 0;
            }
        }
        
        //  Lazy Eviction: Si el slot está ocupado por una IP vieja (más de 10 seg inactiva), se piisa y hasta luego
        if (now - hash_table[index].start_time > 10) {
            break; 
        }

        // 
        index = (index + 1) % HASH_TABLE_SIZE;
        
        //  si dimos la vuelta completa a la tabla
        if (index == start_index) {
            return 0; //tabla llena, ignoramos para no bloquear el sniffer
        }
    }

    // Slot libre o recién desalojado, guardamos la nueva IP
    strncpy(hash_table[index].ip, src_ip, 15);
    hash_table[index].ip[15] = '\0'; // Asegurar terminación nula
    hash_table[index].count = 1;
    hash_table[index].start_time = now;
    hash_table[index].active = 1;

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

    // Solo procesamos IPv4
    if (iph->version != 4) return -1;

    struct in_addr src, dst;
    src.s_addr = iph->saddr;
    dst.s_addr = iph->daddr;

    inet_ntop(AF_INET, &src, info->source_ip, 16);
    inet_ntop(AF_INET, &dst, info->dest_ip, 16);
    info->protocol = iph->protocol;
    info->size = data_size;

    unsigned short iphdrlen = iph->ihl * 4;

    if (iph->protocol == 6) { // TCP
        struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);
        info->src_port = ntohs(tcph->source);
        info->dst_port = ntohs(tcph->dest);
    } else if (iph->protocol == 17) { // UDP
        struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen);
        info->src_port = ntohs(udph->source);
        info->dst_port = ntohs(udph->dest);
    } else { 
        info->src_port = 0;
        info->dst_port = 0;
    } 

    // --- EL FILTRO DE INFRAESTRUCTURA ---
    // Ignoramos 127.0.0.1 (Loopback) y 172.18.x.x (Subred de Docker)
    if (strcmp(info->source_ip, "127.0.0.1") != 0 &&
        strncmp(info->source_ip, "172.18.", 7) != 0 &&
        strncmp(info->dest_ip, "172.18.", 7) != 0) {
        
        // Es tráfico real, lo pasamos al tracker
        pthread_mutex_lock(&tracker_mutex);
        info->is_alert = check_traffic_spike(info->source_ip);
        pthread_mutex_unlock(&tracker_mutex);
    } else {
        // Es tráfico interno, no es alerta nunca
        info->is_alert = 0;
    }
    
    return 0;
}