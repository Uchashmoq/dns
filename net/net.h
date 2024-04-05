#ifndef DNS_NET_H
#define DNS_NET_H
#include <string>
#ifdef WIN32
#include <winsock2.h>
#include <wspiapi.h>
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#endif

typedef sockaddr_in SA_IN;
typedef sockaddr SA;
std::string getLastErrorMessage();
SA_IN inetAddr(const char* addrStr,unsigned short port);
int closeSocket(int sockfd);
#endif
