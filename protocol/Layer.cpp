#include "Layer.h"
#include "errorcode.h"
#include "../lib/Log.h"


const size_t NetworkLayer::BUF_SIZE=10240;

int NetworkLayer::read(Packet &packet) {
    char tmp[BUF_SIZE];
    int len = sizeof(packet.addr);
    auto n = readUdp(sockfd,tmp,BUF_SIZE,&packet.addr);
    if (n<0){
        Log::printf(LOG_ERROR,"receive from udp error : ",getLastErrorMessage().c_str());
        return UDP_RECV_ERR;
    }
    Dns dns;
    if(Dns::resolve(dns,tmp,n)<0){
        Log::printf(LOG_ERROR,"dns resolve error ");
        return DNS_RESOLVE_ERR;
    }
    auto err = Packet::dnsToPacket(packet,dns);
    if(err<0){
        Log::printf(LOG_ERROR,"converting dns into packet error ");
        return err;
    }
    return 0;
}

int NetworkLayer::write(const Packet &packet) {
    return 0;
}
