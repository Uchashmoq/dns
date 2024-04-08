#include "Bytes.hpp"

void reverseBytes(void *buf,size_t len){
    char* p =(char*) buf;
    char tmp;
    for(size_t i=0;i<len/2;i++){
        tmp=p[i];
        p[i]=p[len-i-1];
        p[len-i-1]=tmp;
    }
}
size_t copy(BytesWriter& bw,BytesReader& br,size_t n){
    if(n>bw.writableBytes()) n=bw.writableBytes();
    if(n>br.readableBytes()) n=br.readableBytes();
    memcpy(bw.p+bw.wp,br.p+br.rp,n);
    bw.wp+=n;
    br.rp+=n;
    return n;
}
