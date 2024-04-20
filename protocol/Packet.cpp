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
        Log::printf(LOG_DEBUG,"readPacketHead : payload session id missing");
        return -1;
    }
    packet.sessionId=br.readNum<uint16_t>();

    if(br.readableBytes()<sizeof(uint16_t)){
        Log::printf(LOG_DEBUG,"readPacketHead: payload group id missing");
        return -1;
    }
    packet.groupId=br.readNum<uint16_t>();

    if(br.readableBytes()<sizeof(uint16_t)){
        Log::printf(LOG_DEBUG,"readPacketHead: payload data id missing");
        return -1;
    }
    packet.dataId=br.readNum<uint16_t>();

    if(br.readableBytes()<sizeof(uint8_t)){
        Log::printf(LOG_DEBUG,"readPacketHead: payload type missing");
        return -1;
    }
    packet.type=br.readNum<uint8_t>();
    return 0;
}

int Packet::dnsRespToPacket(Packet &packet, const Dns &dns) {
    int qr , rCode;
    dns.getFlags(&qr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,&rCode);
    if(rCode!=NO_ERR) {
        Log::printf(LOG_DEBUG,"dns has error:\n%s",dns.toString().c_str());
        return -1;
    }
    if(qr!=DNS_RESP) {
        Log::printf(LOG_DEBUG,"in function dnsRespToPacket , qr is not a dns response:\n%s",dns.toString().c_str());
        return -1;
    }
    packet.qr=qr;
    uint8_t payload[BUF_SIZE];
    auto payloadLen  = getValuablePayload(payload,sizeof(payload),dns);
    if (payloadLen<0) return -1;

    BytesReader br(payload,payloadLen);
    readPacketHead(packet,br);
    packet.data=br.readBytes(br.readableBytes());
    return 0;
}

static size_t domainLen(const vector<Bytes>& domain){
    size_t n=0;
    for(auto& b : domain){
        n+=b.size+1;
    }
    return n;
}

static uint8_t randLabelSize(){
    const uint8_t base = 5;
    return (uint8_t)(base+1+abs(rand()) % (MAX_UNENCODED_DATA_LEN_OF_LABEL-base));
}

static record_t randRecordType(){
    uint8_t x = (uint8_t)rand();
    static record_t arr[]={TXT,PTR,CNAME,AAAA,A};
    return arr[x%5];
}

static Query writeToQuery(BytesReader& br ,const vector<Bytes>& domain,uint8_t cnt){
    uint8_t encodedPayload[1024], payload[512] , n =0,dlen = domainLen(domain) ,len ;
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
    for(auto& b : domain){
        q.question.push_back(b);
    }
    return move(q);
}


static vector<Bytes> randDomain(const vector<Bytes>& domain){
    char tmp[8];
    uint32_t  n=(uint32_t)rand()%3+3;
    for(uint32_t i=0;i<n;i++){
        tmp[i]= itoc((uint8_t)rand()%26+10);
    }
    vector<Bytes> v;
    v.emplace_back(tmp,n);
    for(auto& d : domain){
        v.push_back(d);
    }
    return move(v);
}

static record_t randRespType(){
    uint8_t x = (uint8_t)rand();
    static record_t arr[]={TXT,CNAME,PTR};
    return arr[x%3];
}

static Answer writeToAnswer(BytesReader& br,uint8_t cnt,const vector<Bytes>& domain){
    uint8_t encodedPayload[1024],payload[512],len,n=0;
    Answer a;
    a.name= randDomain(domain);
    a.ansType=randRespType();
    BytesWriter bw(payload,sizeof(payload));
    bw.writeNum(cnt);
    while(br.readableBytes()>0){
        len = randLabelSize();
        if(len*2+n>=MAX_TOTAL_DOMAIN_LEN) break;
        copy(bw,br,len);
        auto encodedN = base36encode(encodedPayload,payload,bw.writen());
        a.data.emplace_back(encodedPayload,encodedN);
        n+=encodedN+1;
        bw.jmp();
    }
    a.dataLen=n;
    if(DATA_SHOULD_APPEND0(a.ansType)) a.dataLen+=1;
    return move(a);
}


int Packet::packetToDnsQuery(Dns &dns, const Packet &packet , const vector<Bytes>& domain) {
    uint8_t unencoded[BUF_SIZE];
    BytesWriter bw(unencoded, sizeof(unencoded));
    writePacketHead(bw,packet);
    bw.writeBytes(packet.data);
    dns.setFlag(QR_MASK,DNS_QUERY);
    dns.setFlag(RD_MASK,1);
    BytesReader br(unencoded,bw.writen());
    while(br.readableBytes()>0){
        dns.queries.push_back(writeToQuery(br,domain,(uint8_t)(++dns.questions)));
    }
    return 0;
}
int Packet::packetToDnsResp(Dns &dns,uint16_t transactionId ,const Packet &packet,const vector<Bytes>& domain) {
    uint8_t unencoded[BUF_SIZE];
    BytesWriter bw(unencoded, sizeof(unencoded));
    writePacketHead(bw,packet);
    bw.writeBytes(packet.data);
    dns.setFlag(QR_MASK,DNS_RESP);
    BytesReader br(unencoded,bw.writen());
    while(br.readableBytes()>0){
        dns.answers.push_back(writeToAnswer(br,(uint8_t)(++dns.answerRRs),domain));
    }
    dns.transactionId=transactionId;
    return 0;
}

static bool cmpMyDomain(const vector<Bytes>& names,const vector<Bytes> &myDomain){
    size_t n1=names.size() , n2=myDomain.size();
    for(size_t i =0;i<n2;i++){
        if(names[n1-1-i] != myDomain[n2-1-i]) return false;
    }
    return true;
}
static int getPayloadFromQuery(_Payload& payload,const vector<Bytes>& names,const vector<Bytes> &myDomain){
    if(names.size()<=myDomain.size()) {
        Log::printf(LOG_DEBUG,"getPayloadFromQuery: query domain length exception in request");
        return -1;
    }
    if(!cmpMyDomain(names,myDomain)){
        Log::printf(LOG_WARN,"getPayloadFromQuery: parent domain error in query");
    }
    size_t endPos = names.size()-myDomain.size()  , dlen= domainLen(names);
    uint8_t * tmp=new uint8_t[dlen];
    BytesWriter bw(tmp,dlen);
    for(size_t i=0;i<endPos;i++){
        bw.writeBytes(names[i]);
    }
    uint8_t *decodedPayload=new uint8_t[dlen/2+16];
    auto decodeN = base36decode(decodedPayload, tmp, bw.writen());
    delete[] tmp;
    if(decodeN<0){
        delete[] decodedPayload;
        Log::printf(LOG_DEBUG,"getPayloadFromQuery: base36 decoding error");
        return -1;
    }
    payload.len=decodeN;
    payload.hpDecoded=decodedPayload;
    return 0;
}

static ssize_t getValuableQueryPayload(uint8_t* out,size_t size,const Dns& dns,const vector<Bytes> &myDomain){
    vector<_Payload> queryPayloads;
    ssize_t resultSize=0;

    for(auto& q : dns.queries){
        _Payload payload;
        if(getPayloadFromQuery(payload,q.question,myDomain)<0){
            resultSize=-1;
            goto clear;
        }
        queryPayloads.push_back(payload);
    }
    sort(queryPayloads.begin(),queryPayloads.end());
    resultSize+= splicePayloads(out,size,queryPayloads);

clear:
    clearPayloads(queryPayloads);
    return resultSize;
}

int Packet::dnsQueryToPacket(Packet &packet, const Dns &dns, const vector<Bytes> &myDomain) {
    int qr , rCode;
    dns.getFlags(&qr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,&rCode);
    if(rCode!=NO_ERR) {
        Log::printf(LOG_DEBUG,"dns has error");
        return -1;
    }
    if(qr!=DNS_QUERY) {
        Log::printf(LOG_DEBUG,"in function dnsRespToPacket , qr is not a dns response:\n%s",dns.toString().c_str());
        return -1;
    }
    packet.originalQueries=dns.queries;
    packet.qr=qr;
    uint8_t payload[BUF_SIZE];
    auto payloadLen  = getValuableQueryPayload(payload,sizeof(payload),dns,myDomain);
    if (payloadLen<0) return -1;

    BytesReader br(payload,payloadLen);
    readPacketHead(packet,br);
    packet.data=br.readBytes(br.readableBytes());
    return 0;
}



std::string Packet::toString() {
    stringstream ss;
    ss<<"sessionId: "<<sessionId<<endl;
    ss<<"groupId: "<<groupId<<endl;
    ss<<"dataId: "<<dataId<<endl;
    ss<<"type: "<<type<<endl;
    ss<<"data: "<<data.hexStr()<<endl;
    return ss.str();
}

