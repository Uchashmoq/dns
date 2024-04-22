
#ifndef DNS_PACKETTEST_H
#define DNS_PACKETTEST_H

#include <cstdint>

#define DIFF(b1,b2) diff(b1,sizeof(b1),b2,sizeof(b2))
void clientSendPackets(int argv,char* args[]);
void testQr();
void getDnsServer();

void diff(uint8_t* b1,int len1,uint8_t* b2,int len2);

void testA();

void echoServer();
void echoServer1();

void simulateEchoServer();



#endif //DNS_PACKETTEST_H
