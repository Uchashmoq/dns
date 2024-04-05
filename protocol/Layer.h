#ifndef DNS_LAYER_H
#define DNS_LAYER_H
#include <cstdint>
#include <thread>
#include "../net/udp.h"
#include "Dns.h"
#include "Packet.h"
class NetworkLayer {
private:
    int sockfd;
    std::thread recvThread;
    static const size_t BUF_SIZE;
public:
    NetworkLayer(int sockfd_):sockfd(sockfd_){}
    int read(Packet& packet);
    int write(const Packet& packet);
};

#endif //DNS_LAYER_H
