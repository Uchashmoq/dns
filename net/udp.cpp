#include "udp.h"
#include <iostream>
#include <cstring>

int udpSocket(const SA_IN& addr){
#ifdef WIN32
    static int shouldWsa=1;
    if(shouldWsa){
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::cerr<<"WSAStartup failed. Error Code : %d"<<WSAGetLastError()<<std::endl;
            return -1;
        }
        atexit([](){WSACleanup();});
        shouldWsa=0;
    }
#endif
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) <0) {
        std::cerr<<"Could not create socket"<<std::endl;
        return -1;
    }
    if (bind(sockfd, (SA *)&addr, sizeof(addr)) <0) {
        std::cerr<<"Bind failed :"<< getLastErrorMessage() <<std::endl;
        return -1;
    }
    return sockfd;
}

ssize_t readUdp(int sockfd,void* dst,size_t size,SA_IN* addr){
    socklen_t len = sizeof(SA_IN);
    return recvfrom(sockfd,(char*)dst,size,0,(SA*)&addr,&len);
}
