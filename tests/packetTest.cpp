#include "packetTest.h"
#include <iostream>
#include <cstdlib>
#include "../net/net.h"
#include "../net/udp.h"
#include <thread>
#include "../protocol/Packet.h"
#include "../lib/strings.h"
#define br puts("")
void pbytes(const void* buf,size_t n){
    uint8_t* p= (uint8_t*)buf;
    for(size_t i=0;i<n;i++){
        printf("0x%02x",p[i]);
        if(i!=n-1) printf(", ");
        if((i+1)%8==0) br;
    }
    br;
}

void diff(uint8_t* b1,int len1,uint8_t* b2,int len2){
    int len = len1<len2 ? len1 : len2;
    printf("len1 : %d,len2 : %d\n",len1,len2);
    for(int i=0;i<len;i++){
        if(b1[i]==b2[i]) printf("%02x,%02x",b1[i],b2[i]);
        else printf("[%02x,%02x]",b1[i],b2[i]);
        if(i!=len-1) printf("\t");
        if((i+1)%8==0) br;
    }
    br;
}


void showFlags(const Dns& d){
    int QR=0,OPCODE=0,AA=0,TC=0,RD=0,RA=0,RCODE=0;
    d.getFlags(&QR,&OPCODE,&AA,&TC,&RD,&RA, nullptr,&RCODE);
    printf("QR=%d,OPCODE=%d,AA=%d,TC=%d,RD=%d,RA=%d,RCODE=%d\n",
           QR,OPCODE,AA,TC,RD,RA,RCODE
           );
}

static void showClientReceivedData(uint8_t* p,size_t n){
    using namespace std;
    Dns dns;
    if (Dns::resolve(dns,p,n)<0){
        cerr<<"client resolving dns error"<<endl;
        return;
    }
    cout<<"received dns :"<<endl<<dns.toString();
    Packet packet;
    if (Packet::dnsRespToPacket(packet, dns)<0){
        cerr<<"client dns resp to packet error"<<endl;
        return;
    }
    cout<<"packet : "<<packet.toString()<<endl;
}

void testQr(){
    using namespace std;
    Dns d;
    d.setFlag(RD_MASK,1);
    d.setFlag(QR_MASK,DNS_RESP);
    d.setFlag(RA_MASK,1);
    showFlags(d);
    ::printf("%x",d.flags);
}

void clientSendPackets(int argv,char* args[]){
    using namespace std;
    const char *myDomain, *localDnsAddr="8.8.8.8";
    if(argv<2){
        cerr<<"arg1 : <myDomain> , arg2 : [localDnsAddr]"<<endl;
        exit(1);
    }else{
        myDomain=args[1];
    }
    if(argv>2){
        localDnsAddr=args[2];
    }
    auto sockfd = udpSocket(inetAddr("0.0.0.0",0));
    if(sockfd<=0){
        cerr<<getLastErrorMessage()<<endl;
    }
    thread recv([&](){
        uint8_t buf[1024];
        for(;;){
            SA_IN from;
            memset(&from,0,sizeof(from));
            ssize_t n = readUdp(sockfd, buf, sizeof(buf), &from);
            if(n<=0){
                cerr<<getLastErrorMessage()<<", stop receiving"<<endl;
                break;
            }
            cout<<"received "<<n<<"bytes from "<<sockaddr_inStr(from)<<endl;
            pbytes(buf,n);//打印字节数组内容
            showClientReceivedData(buf,n);//展示dns数据包信息
        }
    });

    SA_IN dnsServerAddr= inetAddr(localDnsAddr,53);
    auto domain = cstrToDomain(myDomain);
    uint8_t sendBuf[1024];
    for(;;){
        string msg;
        cin>>msg;
        Packet packet;
        packet.sessionId=0x10;
        packet.groupId=0x20;
        packet.dataId=0x30;
        packet.type='x';
        packet.data=msg;

        Dns dns;
        Packet::packetToDnsQuery(dns,packet,domain);

        //故意的
        //dns.flags=1;
        auto n = Dns::bytes(dns,sendBuf,sizeof(sendBuf));
        if(n<0){
            cerr<<"dns to bytes error"<<endl;
            continue;
        }
        cout<<"send query:"<<endl;
        cout<<dns.toString()<<endl;
        //pbytes(sendBuf,n);
        if(writeUdp(sockfd,sendBuf,n,dnsServerAddr)<=0){
            cerr<<getLastErrorMessage()<<endl;
            break;
        }
    }
    closeSocket(sockfd);
    recv.join();
    cout<<"exit"<<endl;
}

void testA() {
    using namespace std;
    int sockfd = udpSocket(inetAddr("0.0.0.0",0));
    if(sockfd<=0){
        cerr<<getLastErrorMessage()<<endl;
        exit(1);
    }

    thread recv([&](){
        uint8_t buf[2048];
        for(;;){
            SA_IN from;
            SET_ZERO(from);
            auto n = readUdp(sockfd,buf,sizeof(buf),&from);
            if(n<=0){
                cerr<<getLastErrorMessage()<<endl;
                break;
            }
            cout<<"received "<<n<<" bytes from "<< sockaddr_inStr(from)<<endl;
            pbytes(buf,n);
            Dns d;

            if (Dns::resolve(d, buf, n)<0){
                cerr<<"dns error"<<endl;
            }else{
                cout<<d.toString()<<endl;
            }

        }
    });

    uint8_t sendBuf[2048];
    for(;;){
        string name;
        cin>>name;
        Dns d;
        Query q;
        q.question= cstrToDomain(name.c_str());
        q.queryType=CNAME;
        d.transactionId=::rand();
        d.setFlag(QR_MASK,DNS_QUERY);
        d.setFlag(RD_MASK,1);
        d.questions=1;
        d.queries.push_back(q);

        auto n =Dns::bytes(d,sendBuf,sizeof(sendBuf));
        writeUdp(sockfd,sendBuf,n, inetAddr("114.114.114.114",53));
    }
    closeSocket(sockfd);
    recv.join();
}

void echoServer(){
    using namespace std;
    int sockfd = udpSocket(inetAddr("0.0.0.0",0));
    if(sockfd<=0){
        cerr<<getLastErrorMessage()<<endl;
        exit(1);
    }
    auto myDom = cstrToDomain("tun.k72vb42ffx.xyz");
    uint8_t buf[2048];
    for(;;){
        SA_IN from;
        SET_ZERO(from);
        auto n = readUdp(sockfd,buf,sizeof(buf),&from);
        if(n<=0){
            cerr<<getLastErrorMessage()<<endl;
            break;
        }
        cout<<"received "<<n<<" bytes from "<< sockaddr_inStr(from)<<endl;
        pbytes(buf,n);
        Dns d;

        if (Dns::resolve(d, buf, n)<0){
            cerr<<"dns error"<<endl;
            continue;
        }
        cout<<d.toString()<<endl;

        Packet p;
        if (Packet::dnsQueryToPacket(p, d, myDom)<0){
            continue;
        }
        cout<<p.toString()<<endl;
        p.data+=Bytes("!!!");

        Dns resp;
        Packet::packetToDnsResp(resp,p,myDom);
        ssize_t respN = Dns::bytes(resp, buf, sizeof(buf));
        writeUdp(sockfd,buf,respN,from);
    }

}




