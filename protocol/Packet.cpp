#include "Packet.h"
#include "base36.h"
#include <algorithm>
#include "../lib/Log.h"
#include <cmath>
#include <cstdlib>
#define MAX_UNENCODED_DATA_LEN_OF_LABEL (MAX_LABEL_LEN/2 -3)
using namespace std;
const size_t Packet::BUF_SIZE=1024*16;
const uint32_t maxTTL=300;
const ::uint32_t  minTTL=20;

struct _Payload{
    uint8_t* hpDecoded;
    size_t len;
    _Payload():hpDecoded(nullptr),len(0){}
    bool operator<(const _Payload& other ) const{
        return hpDecoded[0]<other.hpDecoded[0];
    }
    void destroy(){delete[] hpDecoded , len=0;}
};

static int randRange(int min,int max){
    return min + rand()%(max-min);
}

static bool getPayloadFromLabeledData(_Payload& pld ,const vector<Bytes>& data,size_t maxLen){
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
        decoded= nullptr;
        Log::printf(LOG_DEBUG,"fail to base36 decode from data");
        return false;
    }
    pld.hpDecoded=decoded;
    pld.len=(size_t)n;
    return true;
}

static void clearPayloads(vector<_Payload>& payloads){
    for(auto& p : payloads){
        p.destroy();
    }
}

static size_t splicePayloads(uint8_t* buf,size_t len,const vector<_Payload>& payloads){

    BytesWriter bw(buf,len);
    for(auto& pld : payloads){
        if(pld.len>0){
            bw.writeBytes(pld.hpDecoded+1,pld.len-1);
        }
    }
    return bw.writen();
}

static size_t splicePayloads(BytesWriter& bw,const vector<_Payload>& payloads){
    auto n0=bw.writen();
    for(auto& pld : payloads){
        if(pld.len>0){
            bw.writeBytes(pld.hpDecoded+1,pld.len-1);
        }
    }
    return bw.writen()-n0;
}



static ssize_t getPayloadFromAnswers(BytesWriter &bw, const vector<Answer> &answers) {
    vector<_Payload> payloads;
    ssize_t n=-1;
    for(const auto& ans : answers){
        if(USE_LABEL(ans.ansType)){
            _Payload payload;
            if(getPayloadFromLabeledData(payload,ans.data,bw.writableBytes())){
                payloads.push_back(payload);
            }else{
                goto clear;
            }
        }
    }
    sort(payloads.begin(),payloads.end());
    n=splicePayloads(bw,payloads);
    clear:
    clearPayloads(payloads);
    return n;
}
static ssize_t getPayloadFromAdditional(BytesWriter& bw,const vector<Additional>& additional){
    vector<_Payload> payloads;
    ssize_t n=-1;
    for(const auto& add : additional){
        if(USE_LABEL(add.addType)){
            _Payload payloadInName;
            if(getPayloadFromLabeledData(payloadInName,add.name,bw.writableBytes())){
                payloads.push_back(payloadInName);
            }else{
                goto clear;
            }
            _Payload payloadInData;
            if(getPayloadFromLabeledData(payloadInData,add.data,bw.writableBytes())){
                payloads.push_back(payloadInData);
            }else{
                goto clear;
            }
        }
    }
    sort(payloads.begin(),payloads.end());
    n=splicePayloads(bw,payloads);
    clear:
    clearPayloads(payloads);
    return n;
}
static ssize_t getValuablePayload(BytesWriter& bw,const Dns& dns){
    ssize_t answerPayloadLen , additionalPayloadLen;
    if((answerPayloadLen=getPayloadFromAnswers(bw,dns.answers) )<0){
        return -1;
    }
    if((additionalPayloadLen= getPayloadFromAdditional(bw,dns.additions))<0){
        return -1;
    }
    return answerPayloadLen+additionalPayloadLen;
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
    packet.dnsTransactionId=dns.transactionId;
    uint8_t payload[BUF_SIZE];
    BytesWriter bw(payload, sizeof(payload));
    auto payloadLen  = getValuablePayload(bw,dns);
    if (payloadLen<0) return -1;

    BytesReader br(payload,payloadLen);
    if(readPacketHead(packet,br)<0){
        return -1;
    }
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
    static record_t arr[]={TXT,PTR,CNAME};
    return arr[x%5];
}

static Query writeToQuery(BytesReader& br ,record_t qType,const vector<Bytes>& domain,uint8_t cnt){
    uint8_t encodedPayload[1024], payload[512] , n =0,dlen = domainLen(domain) ,len ;
    Query q;
    q.queryType=qType;
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
    if(q.question.empty()){
        Log::printf(LOG_WARN, "write empty data to a query");
    }
    for(auto& b : domain){
        q.question.push_back(b);
    }
    return move(q);
}


static size_t writeToLabeledData(BytesReader& br,uint8_t cnt, vector<Bytes>& dst,size_t maxLen,bool append0){
    uint8_t encodedPayload[1024],payload[512],len,n=0;
    BytesWriter bw(payload,sizeof(payload));
    bw.writeNum(cnt);
    while(br.readableBytes()>0){
        len = randLabelSize();
        if(len*2+n>=maxLen) break;
        copy(bw,br,len);
        auto encodedN = base36encode(encodedPayload,payload,bw.writen());
        dst.emplace_back(encodedPayload,encodedN);
        n+=encodedN+1;
        bw.jmp();
    }
    if(append0&&n>0) n++;
    return n;
}


int Packet::packetToDnsQuery(Dns &dns, uint16_t transactionId,const Packet &packet , const vector<Bytes>& domain) {
    uint8_t unencoded[BUF_SIZE];
    dns.transactionId=transactionId;
    BytesWriter bw(unencoded, sizeof(unencoded));
    writePacketHead(bw,packet);
    bw.writeBytes(packet.data);
    dns.setFlag(QR_MASK,DNS_QUERY);
    dns.setFlag(RD_MASK,1);
    BytesReader br(unencoded,bw.writen());
    while(br.readableBytes()>0){
        dns.queries.push_back(writeToQuery(br,packet.dnsQueryType,domain,(uint8_t)(++dns.questions)));
    }
    return 0;
}

static uint32_t randTTL() {
    return randRange(minTTL,maxTTL);
}

void writeToAnswerDataA(Answer& a){
    uint8_t ip[4];
    for(int i=0;i< sizeof(ip);i++){
        ip[i]= randRange(1,UINT8_MAX-1);
    }
    a.data.emplace_back(ip,sizeof(ip));
    a.dataLen= sizeof(ip);
}
void writeToAnswerDataAAAA(Answer& a){
    uint16_t ip[8];
    for(int i=0;i< sizeof(ip);i++){
        ip[i]= randRange(1,UINT16_MAX-1);
    }
    a.data.emplace_back(ip,sizeof(ip));
    a.dataLen= sizeof(ip);
}

static Answer writeToAnswer(BytesReader& br, const Query& originalQuery, uint8_t cnt){
    Answer a;
    a.ansType=originalQuery.queryType;
    a.ansClass=originalQuery.queryClass;
    a.ttl=randTTL();
    a.name=originalQuery.question;

    switch (a.ansType) {
        case A:
            writeToAnswerDataA(a);
            break;
        case AAAA:
            writeToAnswerDataAAAA(a);
            break;
        default:
            a.dataLen= writeToLabeledData(br,cnt,a.data,MAX_TOTAL_DOMAIN_LEN, DATA_SHOULD_APPEND0(a.ansType));
    }
    return move(a);
}

static record_t randAdditionalType(){
    record_t t[]={NS,CNAME,TXT,PTR};
    return t[randRange(0,4)];
}

static Additional writeToAdditional(BytesReader& br,uint8_t cnt){
    Additional a;
    a.addType=randAdditionalType();
    writeToLabeledData(br,cnt,a.name,MAX_TOTAL_DOMAIN_LEN, true);
    a.dataLen=writeToLabeledData(br,cnt+1,a.data,MAX_TOTAL_DOMAIN_LEN, DATA_SHOULD_APPEND0(a.addType));
    return move(a);
}

int Packet::packetToDnsResp(Dns &dns,uint16_t transactionId ,const Packet &packet) {
    dns.transactionId=transactionId;
    dns.questions=packet.originalQueries.size();
    dns.queries=packet.originalQueries;
    dns.setFlag(QR_MASK,DNS_RESP);


    uint8_t unencoded[BUF_SIZE];
    BytesWriter bw(unencoded, sizeof(unencoded));
    writePacketHead(bw,packet);
    bw.writeBytes(packet.data);
    BytesReader br(unencoded,bw.writen());

    for(size_t i=0;i<packet.originalQueries.size() && br.readableBytes()>0 ;i++){
        if(i>=UINT8_MAX-1) Log::printf(LOG_WARN,"in packetToDnsResp, ansCnt exceeds range of uint8_t");
        dns.answers.push_back(writeToAnswer(br, packet.originalQueries[i],i+1));
    }
    dns.answerRRs=dns.answers.size();

    uint16_t addCnt=1;
    while (br.readableBytes()>0){
        if(addCnt>=UINT8_MAX-1) Log::printf(LOG_WARN,"in packetToDnsResp, addCnt exceeds range of uint8_t");
        dns.additions.push_back(writeToAdditional(br,addCnt));
        addCnt+=2;
    }
    dns.additionalRRs=dns.additions.size();

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
    packet.dnsTransactionId=dns.transactionId;
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


