#ifndef DNS_PACKET_H
#define DNS_PACKET_H
#include "../net/net.h"
#include <stdint.h>
#include "../lib/Bytes.hpp"
#include "Dns.h"
#include <cstring>
struct Packet {
    Packet():dnsTransactionId(0),sessionId(0),groupId(0),dataId(0),type(0),qr(0){
        memset(&addr,0, sizeof(addr));
    }
    SA_IN addr;
    uint16_t dnsTransactionId;
    uint16_t sessionId;
    uint16_t groupId;
    uint16_t dataId;
    uint8_t type;
    uint8_t qr;
    std::vector<Query> originalQueries;
    Bytes data;
    static int dnsRespToPacket(Packet& packet,const Dns& dns);
    static int packetToDnsQuery(Dns &dns, uint16_t transactionId,const Packet &packet , const std::vector<Bytes>& domain);
    static int dnsQueryToPacket(Packet& packet,const Dns& dns, const std::vector<Bytes>& domain);
    static int packetToDnsResp(Dns& dns,uint16_t transactionId ,const Packet& packet,const std::vector<Bytes>& domain);
    std::string toString();

private:
    static const size_t BUF_SIZE;

};
#endif
