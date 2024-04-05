#include "Packet.h"
#include "errorcode.h"
#include "base36.h"
const size_t Packet::BUF_SIZE=10240;
static size_t getValuablePayload(char* buf,size_t len,const Dns& dns){
    BytesWriter bw(buf,len);
    for(auto& q : dns.queries){
        for(auto& b : q.question){
            bw.writeBytes(b.data,b.size);
        }
    }
    for(auto& a : dns.answers){
        for(auto& b : a.name){
            bw.writeBytes(b.data,b.size);
        }
        for(auto& b : a.data){
            bw.writeBytes(b.data,b.size);
        }
    }
    for(auto& ns : dns.nameservers){
        for(auto& b : ns.name){
            bw.writeBytes(b.data,b.size);
        }
        bw.writeBytes(ns.data.data,ns.data.size);
    }
    for(auto& a : dns.additions){
        for(auto& b : a.name){
            bw.writeBytes(b.data,b.size);
        }
        for(auto& b : a.data){
            bw.writeBytes(b.data,b.size);
        }
    }
    return bw.writen();
}
static void writePacketHead(BytesWriter& bw,const Packet& packet){
    bw.writeNum(packet.sessionId);
    bw.writeNum(packet.groupId);
    bw.writeNum(packet.dataId);
    bw.writeNum(packet.type);
    bw.writeBytes(packet.data);
}
int Packet::dnsToPacket(Packet& packet,const Dns& dns){
    int rCode;
    dns.getFlags(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,&rCode);
    if(rCode!=NO_ERR) return DNS_RCODE_ERR;
    char payload[BUF_SIZE]={0},decoded[BUF_SIZE]={0};
    size_t payloadLen = getValuablePayload(payload, sizeof(payload), dns);
    ssize_t decodedLen = base36decode(decoded, payload, payloadLen);
    if(decodedLen<0){
        return BASE36_ERR;
    }
    BytesReader br(decoded,decodedLen);
    if(br.readableBytes()< sizeof(packet.sessionId)) return PACKET_SESSION_ID_MISS_ERR;
    packet.sessionId = br.readNum<uint16_t>();

    if(br.readableBytes()< sizeof(packet.groupId)) return PACKET_GROUP_ID_MISS_ERR;
    packet.groupId = br.readNum<uint16_t>();

    if(br.readableBytes()< sizeof(packet.dataId)) return PACKET_DATA_ID_MISS_ERR;
    packet.dataId = br.readNum<uint16_t>();

    if(br.readableBytes()< sizeof(packet.type)) return PACKET_TYPE_MISS_ERR;
    packet.type = br.readNum<uint8_t>();

    packet.data=br.readBytes(br.readableBytes());

    return 0;
}

static int setPayloadOnlyQuery(Dns& dns,const uint8_t* payload,size_t size){

}


int Packet::PacketToDnsOnlyQuery(Dns &dns, const Packet &packet) {
    uint8_t unencoded[BUF_SIZE],payload[BUF_SIZE];
    BytesWriter bw(unencoded, sizeof(unencoded));
    writePacketHead(bw,packet);
    auto encodedSize = base36encode(payload,unencoded,bw.writen());


}
