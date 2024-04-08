#ifndef DNS_LAYER_H
#define DNS_LAYER_H
#include <cstdint>
#include <thread>
#include "../net/udp.h"
#include "Dns.h"
#include "Packet.h"
#include <string>
class NetworkLayer {
private:
    int sockfd;
    static const size_t BUF_SIZE;
    std::string myDnsServerDomainStr;
    std::vector<Bytes> myDnsServerDomain;
public:
    NetworkLayer(int sockfd_ ,const std::string myDnsServerDomainStr_ );
    int read(Packet& packet);
    int write(const Packet& packet);
};

#endif //DNS_LAYER_H
