#ifndef DNS_PACKET_H
#define DNS_PACKET_H
#include "../net/net.h"
#include <stdint.h>
#include "../lib/Bytes.hpp"
#include "Dns.h"
#include <cstring>
struct Packet {
    Packet():sessionId(0),groupId(0),dataId(0),type(0){
        memset(&addr,0, sizeof(addr));
    }
    SA_IN addr;
    uint16_t sessionId;
    uint16_t groupId;
    uint16_t dataId;
    uint8_t type;
    Bytes data;
    static int dnsRespToPacket(Packet& packet,const Dns& dns);
    static int PacketToDnsQuery(Dns &dns, const Packet &packet , const std::vector<Bytes>& domain);

private:
    static const size_t BUF_SIZE;

};
#endif
