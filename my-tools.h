#ifndef MYTOOLS_H
#define MYTOOLS_H
#include<stdint.h>

typedef struct PseudoHeader{
    uint8_t src_addr[4];
    uint8_t dst_addr[4];
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t tcp_length;
}PSEUDO_HEADER;

// This tool class usable for IP, TCP, UDP Protocol.
class MyTool{
private:
    uint8_t* packet_;
    uint32_t len_;
public:
    MyTool(){
        packet_ = 0;
        len_ = 0;
    } //init packet
    void init(uint8_t* packet, uint32_t len)
    {
        packet_ = packet;
        len_ = len;
    }
    uint16_t Search(uint8_t* bytes, uint8_t bytesLen);
    uint16_t GetCheckSum();
};

#endif // MYTOOLS_H
