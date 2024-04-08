#include "Packet.h"
#include "base36.h"
#include <algorithm>
#include "../lib/Log.h"
#include <cmath>
#include <cstdlib>
#define MAX_UNENCODED_DATA_LEN_OF_LABEL (MAX_LABEL_LEN/2 -3)
using namespace std;
const size_t Packet::BUF_SIZE=10240;
struct _Payload{
    uint8_t* hpDecoded;
    size_t len;
    _Payload():hpDecoded(nullptr),len(0){}
    bool operator<(const _Payload& other ) const{
        return hpDecoded[0]<other.hpDecoded[0];
    }
};

static bool getPayloadFromData(_Payload& pld ,const vector<Bytes>& data,size_t maxLen){
    uint8_t *tmp = new uint8_t[maxLen];
    BytesWriter bw(tmp,maxLen);
    for(auto& b : data){
        bw.writeBytes(b);
    }
    uint8_t* decoded = new uint8_t [maxLen/2+16];
    auto n = base36decode(decoded,tmp,bw.writen());
    delete[] tmp;
    if(n<0){
        delete[] decoded;
        Log::printf(LOG_DEBUG,"fail to base36 decode from data");
        return false;
    }
    pld.hpDecoded=decoded;
    pld.len=(size_t)n;
    return true;
}

static void clearPayloads(vector<_Payload>& payloads){
    for(auto& p : payloads){
        delete[] p.hpDecoded;
        p.hpDecoded= nullptr;
    }
}

static size_t splicePayloads(uint8_t* buf,size_t len,const vector<_Payload>& payloads){
    BytesWriter bw(buf,len);
    for(auto& pld : payloads){
        bw.writeBytes(pld.hpDecoded+1,pld.len-1);
    }
    return bw.writen();
}

static ssize_t getValuablePayload(uint8_t* buf,size_t len,const Dns& dns){
    vector<_Payload> answerPayloads , additionPayloads;
    ssize_t resultSize=0;

    for(auto& a : dns.answers){
       _Payload payload;
       if(!getPayloadFromData(payload,a.data,a.dataLen)) {
           resultSize=-1;
           goto clear;
       }
       answerPayloads.push_back(payload);
    }

    for(auto& a : dns.additions){
        _Payload payload;
        if(!getPayloadFromData(payload,a.data,a.dataLen)) {
            resultSize=-1;
            goto clear;
        }
        additionPayloads.push_back(payload);
    }
    sort(answerPayloads.begin(),answerPayloads.end());
    sort(additionPayloads.begin() , additionPayloads.end());

    resultSize+= splicePayloads(buf,len,answerPayloads);
    resultSize+= splicePayloads(buf+resultSize,len-resultSize,additionPayloads);

clear:
    clearPayloads(answerPayloads);
    clearPayloads(additionPayloads);
    return resultSize;
}

static void writePacketHead(BytesWriter& bw,const Packet& packet){
    bw.writeNum(packet.sessionId);
    bw.writeNum(packet.groupId);
    bw.writeNum(packet.dataId);
    bw.writeNum(packet.type);
}

static int readPacketHead(Packet& packet,BytesReader& br){
    if(br.readableBytes()<sizeof(uint16_t)){
        Log::printf(LOG_DEBUG,"payload session id missing");
        return -1;
    }
    packet.sessionId=br.readNum<uint16_t>();

    if(br.readableBytes()<sizeof(uint16_t)){
        Log::printf(LOG_DEBUG,"payload group id missing");
        return -1;
    }
    packet.groupId=br.readNum<uint16_t>();

    if(br.readableBytes()<sizeof(uint16_t)){
        Log::printf(LOG_DEBUG,"payload data id missing");
        return -1;
    }
    packet.dataId=br.readNum<uint16_t>();

    if(br.readableBytes()<sizeof(uint8_t)){
        Log::printf(LOG_DEBUG,"payload type missing");
        return -1;
    }
    packet.type=br.readNum<uint8_t>();
    return 0;
}

int Packet::dnsRespToPacket(Packet &packet, const Dns &dns) {
    int qr , rCode;
    dns.getFlags(&qr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,&rCode);
    if(rCode!=NO_ERR) {
        Log::printf(LOG_DEBUG,"dns has error");
        return -1;
    }
    if(qr!=DNS_RESP) {
        Log::printf(LOG_DEBUG,"in function dnsRespToPacket , qr is not a dns response");
        return -1;
    }
    uint8_t payload[BUF_SIZE];
    auto payloadLen  = getValuablePayload(payload,sizeof(payload),dns);
    if (payloadLen<0) return -1;

    BytesReader br(payload,payloadLen);
    readPacketHead(packet,br);
    packet.data=br.readBytes(br.readableBytes());
    return 0;
}

static inline size_t domainLen(const vector<Bytes>& domain){
    size_t n=0;
    for(auto& b : domain){
        n+=b.size+1;
    }
    return n;
}

static inline  uint8_t randLabelSize(){
    const uint8_t base = 5;
    return (uint8_t)(base+1+abs(rand()) % (MAX_UNENCODED_DATA_LEN_OF_LABEL-base));
}
/*
A记录：54%
AAAA记录：23%
CNAME记录：10%
MX记录：6%
PTR记录：4%
TXT记录：3%
  */
static record_t randRecordType(){
    uint8_t x = abs(rand())%100;
    if(0<=x && x<3) return TXT;
    if(3<=x && x<7) return PTR;
    if(7<=x && x<13) return MX;
    if(13<=x && x<23) return CNAME;
    if(23<=x && x<46) return AAAA;
    return A;
}

static Query writeToQuery(BytesReader br ,const vector<Bytes>& domain,uint8_t cnt){
    uint8_t encodedPayload[1024], payload[512] , n =2,dlen = domainLen(domain) ,len ;
    Query q;
    q.queryType=randRecordType();
    BytesWriter bw(payload,sizeof(payload));
    bw.writeNum(cnt);
    while(br.readableBytes()>0){
        len = randLabelSize();
        if(len*2+n+dlen>=MAX_TOTAL_DOMAIN_LEN) break;
        copy(bw,br,len);
        auto encodedN = base36encode(encodedPayload,payload,bw.writen());
        q.question.emplace_back(encodedPayload,encodedN);
        n+=encodedN;
        bw.jmp();
    }
    return move(q);
}


int Packet::PacketToDnsQuery(Dns &dns, const Packet &packet , const vector<Bytes>& domain) {
    uint8_t unencoded[BUF_SIZE];
    BytesWriter bw(unencoded, sizeof(unencoded));
    writePacketHead(bw,packet);
    bw.writeBytes(packet.data);

    BytesReader br(unencoded,bw.writen());
    while(br.readableBytes()>0){
        dns.queries.push_back(writeToQuery(br,domain,(uint8_t)(++dns.questions)));
    }
    return 0;
}
