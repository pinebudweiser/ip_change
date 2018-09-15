#include <iostream>
#include <libnet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "my-tools.h"


/* */
#define MAX_PACKET      0xFFFF
#define PROTOCOL_TCP	0x6
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

using namespace std;

int queue_processor(nfq_q_handle *CrtHandle, nfgenmsg *nfmsg,
                     nfq_data *packet_handler, void *data)
{
    uint32_t pktLen; // IP+TCP+HTTP, HTTP
    int id;
    uint8_t* packet;
    IP* ipHeader;
    TCP* tcpHeader;
    nfqnl_msg_packet_hdr *packetHeader;
    MyTool binTool;
    uint16_t result;
    PSEUDO_HEADER pse;
    uint8_t* my_packet = 0;

    packetHeader = nfq_get_msg_packet_hdr(packet_handler);
    if (packetHeader) {
        id = ntohl(packetHeader->packet_id);
    }
    pktLen = nfq_get_payload(packet_handler, &packet); // get packet - starting IP
    ipHeader = (IP*)(packet);

    if(ipHeader->ip_v == VERSION_IPV4)
    {
        //memcpy(&(ipHeader->ip_dst), "\x7D\x8E\x43\x8E", 4);
        ipHeader->ip_sum = 0;
        binTool.init((uint8_t*)ipHeader,sizeof(IP)); // arg1 = index of data, arg2 = HTTP data size.
        ipHeader->ip_sum = ntohs(binTool.GetCheckSum());
        switch(ipHeader->ip_p)
        {
            case IPPROTO_ICMP:
                break;
            case IPPROTO_TCP:
                tcpHeader = (TCP*)(packet+(ipHeader->ip_hl << 2));
                //if(ntohs(tcpHeader->th_dport) == HTTP_PORT) // response data
                //{
                tcpHeader->th_sum = 0;
                memcpy(pse.src_addr, &(ipHeader->ip_src), 4);
                memcpy(pse.dst_addr, &(ipHeader->ip_dst), 4);
                pse.protocol = ipHeader->ip_p;
                pse.tcp_length = htons(tcpHeader->th_off << 2);
                binTool.init((uint8_t*)tcpHeader, pktLen-(ipHeader->ip_hl << 2));
                tcpHeader->th_sum = htons(binTool.GetCheckSum());
                return nfq_set_verdict(CrtHandle, id, NF_ACCEPT, pktLen, packet);
                //}
                break;
            case IPPROTO_UDP:
                break;
        }

    }
    //return nfq_set_verdict(CrtHandle, id, NF_ACCEPT, pktLen, packet);
}

int main(int argc, char** argv)
{
    nfq_handle* nfqOpenHandle;
    nfq_q_handle* nfqCrtHandle;
    int nfqDescriptor;
    int pk_len;
    uint8_t* packet;
    char buf[4096];

    if(argc != 3)
        printf("Usage: ip_change <before_ip><change_ip>\n");


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
