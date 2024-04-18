#ifndef DNS_NET_H
#define DNS_NET_H
#include <string>
#include <vector>

#ifdef WIN32

#include <wspiapi.h>
#include<iphlpapi.h>
#include <winsock2.h>
#include "../lib/Bytes.hpp"
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#endif

#define SET_ZERO(o) memset(&o,0,sizeof(o))
typedef sockaddr_in SA_IN;
typedef sockaddr SA;
std::string getLastErrorMessage();
SA_IN inetAddr(const char* addrStr,unsigned short port);
std::string sockaddr_inStr(const SA_IN& addr);
std::vector<Bytes> cstrToDomain(const char* str);

int closeSocket(int sockfd);
#endif
