#include "Layer.h"
#include "../lib/Log.h"
#include "../lib/strings.h"

using namespace std;
const size_t NetworkLayer::BUF_SIZE=10240;

NetworkLayer::NetworkLayer(int sockfd_, const string myDnsServerDomainStr_) {
    sockfd=sockfd_;
    myDnsServerDomainStr=myDnsServerDomainStr_;
    for(auto &s : splitString(myDnsServerDomainStr_,'.') ){
        myDnsServerDomain.emplace_back(s);
    }
}


int NetworkLayer::read(Packet &packet) {
    char tmp[BUF_SIZE];
    int len = sizeof(packet.addr);
    auto n = readUdp(sockfd,tmp,BUF_SIZE,&packet.addr);
    if (n<0){
        Log::printf(LOG_ERROR,"receive from udp error : ",getLastErrorMessage().c_str());
        return -1;
    }
    Dns dns;
    if(Dns::resolve(dns,tmp,n)<0){
        Log::printf(LOG_ERROR,"dns resolve error ");
        return -1;
    }
    auto err = Packet::dnsRespToPacket(packet,dns);
    if(err<0){
        Log::printf(LOG_ERROR,"converting dns into packet error ");
        return err;
    }
    return 0;
}

int NetworkLayer::write(const Packet &packet) {
    Dns dns;


}
