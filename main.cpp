#include <iostream>
#include <libnet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "my-tools.h"

#define MAX_PACKET      0xFFFF
#define VERSION_IPV4	0x4
#define HTTP_PORT		80

/* nfq struct typedefing */
typedef struct nfq_q_handle nfq_q_handle;
typedef struct nfgenmsg nfgenmsg;
typedef struct nfq_data nfq_data;
typedef struct nfq_handle nfq_handle;
typedef struct nfq_q_handle nfq_q_handle;
typedef struct nfqnl_msg_packet_hdr nfqnl_msg_packet_hdr;

/* libnet struct typedefing */
typedef struct libnet_ipv4_hdr IP;
typedef struct libnet_tcp_hdr TCP;

/* static */
static char* before_ip;
static char* after_ip;

using namespace std;

int queue_processor(nfq_q_handle *CrtHandle, nfgenmsg *nfmsg,
                     nfq_data *packet_handler, void *data){
    uint32_t pktLen; // IP+TCP+HTTP, HTTP
    int id;
    uint8_t* packet;
    IP* ipHeader;
    TCP* tcpHeader;
    nfqnl_msg_packet_hdr *packetHeader;
    MyTool binTool;
    PSEUDO_HEADER pse;
    uint8_t* my_packet = 0;

    packetHeader = nfq_get_msg_packet_hdr(packet_handler);
    if (packetHeader)
        id = ntohl(packetHeader->packet_id);
    pktLen = nfq_get_payload(packet_handler, &packet); // get packet - starting IP
    ipHeader = (IP*)(packet);

    if(ipHeader->ip_v == VERSION_IPV4){
        ipHeader->ip_sum = 0;
        printf("Dest ip = %s\n", inet_ntoa(ipHeader->ip_dst));
        printf("before_ip = %s\n", before_ip);
        if(inet_addr(inet_ntoa(ipHeader->ip_dst)) == inet_addr(before_ip))
        {
            inet_aton(after_ip, &(ipHeader->ip_dst));
            printf("Change DestIP : %s\n", inet_ntoa(ipHeader->ip_dst));
        }
        binTool.init((uint8_t*)ipHeader,sizeof(IP)); // arg1 = index of data, arg2 = HTTP data size.
        ipHeader->ip_sum = htons(binTool.GetCheckSum());
        switch(ipHeader->ip_p)
        {
            case IPPROTO_ICMP:
                break;
            case IPPROTO_TCP:
                tcpHeader = (TCP*)(packet+(ipHeader->ip_hl << 2));
                tcpHeader->th_sum = 0; // checksum init
                /* set pseudo_header */
                memcpy(pse.src_addr, &(ipHeader->ip_src), 4);
                memcpy(pse.dst_addr, &(ipHeader->ip_dst), 4);
                pse.protocol = ipHeader->ip_p;
                pse.tcp_length = htons(pktLen - (ipHeader->ip_hl << 2)); // tcp_header + data
                /* end */
                my_packet = (uint8_t*)malloc(pktLen - (ipHeader->ip_hl << 2) + sizeof(PSEUDO_HEADER));
                memcpy(my_packet, &pse, sizeof(PSEUDO_HEADER));
                memcpy(my_packet + sizeof(PSEUDO_HEADER), tcpHeader, pktLen - (ipHeader->ip_hl<<2));
                binTool.init(my_packet, pktLen - (ipHeader->ip_hl << 2) + sizeof(PSEUDO_HEADER));
                tcpHeader->th_sum = htons(binTool.GetCheckSum());
                free(my_packet);
                break;
            case IPPROTO_UDP:
                break;
        }

    }
    return nfq_set_verdict(CrtHandle, id, NF_ACCEPT, pktLen, packet);
}

int main(int argc, char** argv)
{
    nfq_handle* nfqOpenHandle;
    nfq_q_handle* nfqCrtHandle;
    int nfqDescriptor;
    int pk_len;
    uint8_t* packet;
    char buf[4096];

    if(argc != 3){
        printf("Usage: ip_change <before_ip><change_ip>\n");
        return 0;
    }
    before_ip = argv[1];
    after_ip = argv[2];


    nfqOpenHandle = nfq_open();
    if (!nfqOpenHandle)
    {
        printf("nfqHandle create failed.\n");
        return 0;
    }
    nfqCrtHandle = nfq_create_queue(nfqOpenHandle, 0, &queue_processor, NULL);
    if (!nfqCrtHandle)
    {
        printf("nfqQueue create failed.\n");
        return 0;
    }
    if (nfq_set_mode(nfqCrtHandle, NFQNL_COPY_PACKET, MAX_PACKET))
    {
        printf("nfqSetmode COPY_PACKET failed.\n");
        return 0;
    }
    nfqDescriptor = nfq_fd(nfqOpenHandle);
    if (!nfqDescriptor)
    {
        printf("init_nfq_objects() failed..!");
        return 0;
    }
    while(true)
    {
        if((pk_len = recv(nfqDescriptor, buf, sizeof(buf), 0)) >= 0)
        {
            nfq_handle_packet(nfqOpenHandle, buf, pk_len);
            continue;
        }
        if(pk_len < 0)
        {
            printf("[Err] Packet loss!\n");
            continue;
        }
    }
    nfq_destroy_queue(nfqCrtHandle);
    nfq_close(nfqOpenHandle);
    return 0;
}
