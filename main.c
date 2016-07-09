#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

void callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    static int count = 1;

    struct libnet_ethernet_hdr *etherhdr;
    struct libnet_ipv4_hdr *iphdr;
    struct libnet_tcp_hdr *tcphdr;

    etherhdr = (struct libnet_ethernet_hdr*)(packet);
    packet += sizeof(struct libnet_ethernet_hdr);

    iphdr = (struct libnet_ipv4_hdr*)(packet);
    packet += sizeof(struct libnet_ipv4_hdr);

    tcphdr = (struct libnet_tcp_hdr*)(packet);

    printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);

    if (ntohs(etherhdr->ether_type) == ETHERTYPE_IP){
        if (iphdr->ip_p == 0x6){
            printf("Src MAC Address : ");
            for (int i = 0; i < 6; i++){
                printf("%02X", etherhdr->ether_shost[i]);
                if(i == 5)
                    printf("\n");
                else
                    printf(":");
            }
            printf("Dst MAC Address : ");
            for (int i = 0; i < 6; i++){
                printf("%02X", etherhdr->ether_dhost[i]);
                if(i == 5)
                    printf("\n");
                else
                    printf(":");
            }
            printf("Src IP Address : %s\n", inet_ntoa(iphdr->ip_src));
            printf("Dst IP Address : %s\n", inet_ntoa(iphdr->ip_dst));
            printf("Src Port : %d\n", ntohs(tcphdr->th_sport));
            printf("Dst Port : %d\n", ntohs(tcphdr->th_dport));
        }
        else
            printf("NOT TCP Packet\n");
    }
    else
        printf("NOT IP Packet\n");

    printf("\n\n");
}

int main()
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    bpf_u_int32 pMask;
    bpf_u_int32 pNet;

    dev = pcap_lookupdev(errbuf);
    printf("\n ---You opted for device [%s] to capture packets---\n\n Starting capture...\n", dev);

    if(dev == NULL){
        printf("\n[%s]\n", errbuf);
        return -1;
    }

    pcap_lookupnet(dev, &pNet, &pMask, errbuf);

    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);

    if(descr == NULL){
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    pcap_loop(descr, -1, callback, NULL);
    return 0;
}
