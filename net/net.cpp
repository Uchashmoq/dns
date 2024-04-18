#include "net.h"
#include <cstring>
#include "../lib/strings.h"
using namespace std;
SA_IN inetAddr(const char *addrStr, unsigned short port) {
    SA_IN addr;
    memset(&addr,0, sizeof(addr));
    addr.sin_family = AF_INET;
    if(addrStr== nullptr || strcmp(addrStr,"0.0.0.0")==0){
        addr.sin_addr.s_addr = INADDR_ANY;
    }
    else if (inet_pton(AF_INET, addrStr, &(addr.sin_addr))!=1 ){
        perror("inet_pton");
    }
    addr.sin_port = htons(port);
    return addr;
}

string sockaddr_inStr(const SA_IN &addr) {
    string addrStr = inet_ntoa(addr.sin_addr);
    auto port = ntohs(addr.sin_port);
    return addrStr+":"+ to_string(port);
}


string getLastErrorMessage() {
#ifdef WIN32
    char errorMessage[2048];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, WSAGetLastError(),
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  errorMessage, sizeof(errorMessage), NULL);
    return errorMessage;
#else
    return strerror(errno);
#endif
}

int closeSocket(int sockfd) {
#ifdef WIN32
    return closesocket(sockfd);
#else
    return close(sockfd);
#endif
}

vector<Bytes> cstrToDomain(const char *str) {
    const vector<string> &strs = splitString(str, '.');
    vector<Bytes> v;
    for(const auto& s : strs){
        v.emplace_back(s);
    }
    return move(v);
}

