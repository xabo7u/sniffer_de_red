#include <pcap.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>        
#include <netinet/tcp.h>       
#include <netinet/udp.h>       
#include <arpa/inet.h> 

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    printf("Capa Enlace\n");
    printf("Direccion MAC de destino: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
    printf("Direccion MAC de origen: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
    printf("Tipo de protocolo: 0x%04x\n", ntohs(eth->h_proto));

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    printf("Capa Red\n");
    printf("IP de origen: %s\n", inet_ntoa(ip_header->ip_src));
    printf("IP de destino: %s\n", inet_ntoa(ip_header->ip_dst));

    printf("Capa Transporte\n");
    switch(ip_header->ip_p){
        case IPPROTO_TCP:
            printf("TCP/n");
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
            printf("Puerto TCP de origen: %d, destino %d\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
            printf("Numero de secuencia: %u\n", ntohl(tcp_header->th_seq));
            printf("Numero de acuse recibido: %u\n", ntohl(tcp_header->th_ack));
            break;
        case IPPROTO_UDP:
            printf("UDP\n");
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
            printf("Puerto UDP de origen: %d, destino: %d\n", ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
            break;
        case IPPROTO_ICMP:
            printf("ICMP\n");
            break;
        default:
            printf("Desconocido\n");
            break;
    }

    printf("\n");
}

int main(){
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *devs, *dev; 
    
    if(pcap_findalldevs(&devs, error) == -1){
        printf("Error Find Devs: %s\n",error);
        return 1;
    }

    if(devs == NULL){
        printf("ERROR devs: %s\n");
        return 1;
    }

    dev = devs;

    handle = pcap_open_live(dev->name,BUFSIZ,1,1000,error);
    if (handle == NULL){
        printf("Error open live: %s\n",error);
        return 1;
    }

    if(pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        printf("Error en la captura: %s\n", pcap_geterr(handle));
        return 1;
    }

    pcap_close(handle);
    pcap_freealldevs(devs);
    return 0;
}