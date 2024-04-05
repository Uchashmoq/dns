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

