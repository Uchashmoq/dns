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
    cout<<(string)packet.data<<endl;
}

void testQr(){
    using namespace std;
    Dns d;
    d.setFlag(RD_MASK,1);
    d.setFlag(QR_MASK,DNS_RESP);
    d.setFlag(RA_MASK,1);
    ::printf("%x",d.flags);
}

void clientSendPackets(int argv,char* args[]){
    using namespace std;
    const char *myDomain, *localDnsAddr="114.114.114.114";
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
        Packet::packetToDnsQuery(dns,::rand(),packet,domain);

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
    int sockfd = udpSocket(inetAddr("0.0.0.0",53));
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
        Packet::packetToDnsResp(resp,d.transactionId,p);
        ssize_t respN = Dns::bytes(resp, buf, sizeof(buf));
        puts("send :");
        writeUdp(sockfd,buf,respN,from);
        cout<<"sent "<<respN<<endl<<resp.toString();
    }

}
void repeat(std::string& s,int n){
    auto s1 = s;
    for(int i=0;i<n;i++){s+=s1;}
}
void simulateEchoServer() {
    using namespace std;
    Packet p1,p2,p3,p4;
    Dns d1,d2,d3,d4;
    string msg = "abcdefg";
    //repeat(msg,500);
    auto myDom = cstrToDomain("tun.k72vb42ffx.xyz");
    p1.dnsTransactionId=0x1234;
    p1.sessionId=0x1234;
    p1.groupId=0x1234;
    p1.dataId=0x1234;
    p1.type='x';
    p1.data=msg;
    const int size = 1024*128;
    uint8_t buf1[size]={0} , buf2[size]={0};

    Packet::packetToDnsQuery(d1,::rand(),p1,myDom);
    ssize_t n1 = Dns::bytes(d1, buf1, sizeof(buf1));

    cout<<"p1:"<<endl<<p1.toString()<<endl<<"d1:"<<d1.toString();
   // pbytes(buf1,n1);

    auto res1 = Dns::resolve(d2,buf1,n1);
    if(res1<0) {
        cerr<<"resolve error1"<<endl;
        exit(1);
    }
    Packet::dnsQueryToPacket(p2,d2,myDom);
    cout<<(string)p2.data<<endl;
    p2.data+="!!!";
    p3=p2;
    Packet::packetToDnsResp(d3,d2.transactionId,p3);
    //cout<<"d3:\n"<<d3.toString();
    auto n2 = Dns::bytes(d3,buf2, sizeof(buf2));

    auto res2 = Dns::resolve(d4,buf2,n2);
    if(res2<0) {
        cerr<<"resolve error2"<<endl;
        exit(1);
    }

    Packet::dnsRespToPacket(p4,d4);
    //pbytes(buf2,n2);
    cout<<"d4:"<<endl<<d4.toString()<<"p4:"<<endl<<p4.toString();
    cout<<(string)p4.data;

}




