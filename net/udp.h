#ifndef DNS_UDP_H
#define DNS_UDP_H
#include "net.h"
#include <cstdlib>
int udpSocket(const SA_IN& addr);
ssize_t readUdp(int sockfd,void* dst,size_t size,SA_IN* addr);
ssize_t writeUdp(int sockfd,const void* src,size_t size,const SA_IN& addr);

#endif //DNS_UDP_H
