#include "my-tools.h"
#include <stdio.h>
#include <string.h>

uint16_t MyTool::Search(uint8_t* bytes, uint8_t bytesLen)
{
    uint8_t* index;

    if(len_ != 0)
    {
        index = (uint8_t*)memchr(packet_, bytes[0], len_);
        do{
            uint8_t match = 0;

            index++;
            index = (uint8_t*)memchr(index, bytes[0], len_);
            if(index == 0)
                break;
            for(int i = 0; i < bytesLen; i++)
            {
                if(index[i] == (uint8_t)bytes[i])
                    match++;
            }
            if(match == bytesLen)
                memcpy(index, "HOOKING", bytesLen);
        }while(index);
    }
    return 0; // false
}

uint16_t MyTool::GetCheckSum()
{
    uint32_t result = 0;
    uint8_t carry = 0;
    int i = 0;

    for(i = 0; i < len_-1; i+=2)
        result += ((packet_[i] << 8) + (packet_[i+1]));
    if(len_ % 2) // if odd num
        result += packet_[i] << 8;
    carry = (result & 0xFF0000) >> 16;
    result += carry;
    result = ~result;
    return (uint16_t)result;
}
