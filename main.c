#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

void callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    static int count = 1;

    unsigned char Dstmac[6];
    unsigned char Srcmac[6];
    unsigned short ether_type;

    struct in_addr Srcip;
    struct in_addr Dstip;
    unsigned char ip_protocol;

    unsigned short Srcport;
    unsigned short Dstport;

    for(int i=0;i<6;i++)
        Dstmac[i]=*(packet++);

    for(int i=0;i<6;i++)
        Srcmac[i]=*(packet++);

    ether_type = ntohs(*((short*)(packet)));

    ip_protocol = *(packet+11);

    Srcip.s_addr = *((long*)(packet+14));

    Dstip.s_addr = *((long*)(packet+18));

    Srcport = ntohs(*((short*)(packet+22)));

    Dstport = ntohs(*((short*)(packet+24)));

    printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);

    if (ether_type == 0x800){
        if (ip_protocol == 0x6){
            printf("Src MAC Address : ");
            for (int i = 0; i < 6; i++){
                printf("%02X", Srcmac[i]);
                if(i == 5)
                    printf("\n");
                else
                    printf(":");
            }
            printf("Dst MAC Address : ");
            for (int i = 0; i < 6; i++){
                printf("%02X", Dstmac[i]);
                if(i == 5)
                    printf("\n");
                else
                    printf(":");
            }
            printf("Src IP Address : %s\n", inet_ntoa(Srcip));
            printf("Dst IP Address : %s\n", inet_ntoa(Dstip));
            printf("Src Port : %d\n", Srcport);
            printf("Dst Port : %d\n", Dstport);
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
