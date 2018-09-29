#include <iostream>
#include <set>
#include <algorithm> // find_if
#include <libnet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "my-tools.h"
#include "flow-tester.h"

#define MAX_PACKET      0xFFFF
#define VERSION_IPV4	0x4
#define HTTP_PORT		80

using namespace std;

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
static uint32_t before_ip;
static uint32_t after_ip;
static set<FlowManager*> outputInstance;

uint32_t str_to_ip(char* str)
{
    uint8_t arr[4];
    uint32_t ipValue = 0;

    sscanf(str,"%d.%d.%d.%d"
           ,&arr[0],&arr[1],&arr[2],&arr[3]);
    ipValue = (arr[0]<<24) + (arr[1]<<16) + (arr[2]<<8) + (arr[3]);

    return ipValue;
}

int queue_processor(nfq_q_handle *CrtHandle, nfgenmsg *nfmsg,
                     nfq_data *packet_handler, void *data){
    uint8_t hookType; // 1 -> INPUT, 2 -> FORWARD, 3 -> OUTPUT
    uint8_t* packet;
    uint32_t pktLen;
    IP* ipHeader;
    TCP* tcpHeader;
    nfqnl_msg_packet_hdr *packetHeader;
    MyTool binTool;
    FlowManager inputFlow;
    FlowManager* outputFlow;
    PSEUDO_HEADER pse;
    int id;
    uint8_t* my_packet = 0;
    set<FlowManager*>::iterator flowIter;

    packetHeader = nfq_get_msg_packet_hdr(packet_handler);
    if (packetHeader){
        id = ntohl(packetHeader->packet_id);
        hookType = packetHeader->hook;
    }
    pktLen = nfq_get_payload(packet_handler, &packet); // get packet - starting IP
    ipHeader = (IP*)(packet);

    if(ipHeader->ip_v == VERSION_IPV4){
        switch(ipHeader->ip_p)
        {
            case IPPROTO_ICMP:
                break;
            case IPPROTO_TCP:
                ipHeader->ip_sum = 0;
                tcpHeader = (TCP*)(packet+(ipHeader->ip_hl << 2));
                if(hookType == 3 && (ipHeader->ip_dst.s_addr == before_ip)) // Output
                {
                    outputFlow = (FlowManager*)malloc(sizeof(FlowManager));
                    outputFlow->init(ipHeader->ip_src.s_addr, ipHeader->ip_dst.s_addr,
                                    ntohs(tcpHeader->th_sport), ntohs(tcpHeader->th_dport));
                    outputInstance.insert(outputFlow);
                    ipHeader->ip_dst.s_addr = after_ip; //change ip
                }
                if(hookType == 1 && (ipHeader->ip_src.s_addr == after_ip)) // Input
                {
                    inputFlow.init(before_ip, ipHeader->ip_dst.s_addr,
                                   ntohs(tcpHeader->th_sport), ntohs(tcpHeader->th_dport));
                    inputFlow.reverse();
                    for(flowIter = outputInstance.begin(); flowIter != outputInstance.end(); flowIter++){
                        if(inputFlow == *flowIter){
                            ipHeader->ip_src.s_addr = before_ip;
                            (*flowIter)->ChangeValue(true);
                        }
                    }
                }
                ipHeader->ip_sum = 0;
                binTool.init((uint8_t*)ipHeader,sizeof(IP)); // index of data, HTTP data size.
                ipHeader->ip_sum = htons(binTool.GetCheckSum());
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
    before_ip = ntohl(str_to_ip(argv[1]));
    after_ip = ntohl(str_to_ip(argv[2]));

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
