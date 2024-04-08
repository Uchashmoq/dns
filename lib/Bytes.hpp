#ifndef DNS_BYTES_HPP
#define DNS_BYTES_HPP
#include <cstdlib>
#include <cstring>
#include <string>
#include <iomanip>
#include <sstream>

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 1
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 0
#endif

void reverseBytes(void *buf,size_t len);
struct Bytes{
    uint8_t *data;
    size_t size;
    Bytes() : data(nullptr) ,size(0) {}
    Bytes(size_t size_){
        data=new uint8_t [size_];
        size=size_;
    }

    Bytes(const void *data_,size_t size_){
        size=size_;
        data=new uint8_t [size];
        memcpy(data,data_,size);
    }
    Bytes(const char* cstr) : Bytes(cstr, strlen(cstr)){}
    Bytes(const std::string& str): Bytes(str.c_str(),str.size()){}
    Bytes(const Bytes& other){
        size=other.size;
        data=new uint8_t [size];
        memcpy(data,other.data,size);
    }
    Bytes(Bytes&& other) noexcept{
        size=other.size;
        data=other.data;
        other.data= nullptr;
        other.size=0;
    }
    Bytes& operator=(const Bytes& other){
        if(this!=&other){
            size=other.size;
            delete[] data;
            data=new uint8_t [size];
            memcpy(data,other.data,size);
        }
        return *this;
    }
    Bytes& operator=(Bytes&& other) noexcept{
        size=other.size;
        delete[] (char *)data;
        data=other.data;
        other.data= nullptr;
        other.size=0;
        return *this;
    }
    Bytes& operator+=(const Bytes& other){
        uint8_t * newBuf = new uint8_t [size+other.size];
        memcpy(newBuf,data,size);
        memcpy(newBuf+size,other.data,other.size);
        delete[] (char *)data;
        data=newBuf;
        size+=other.size;
        return *this;
    }
    bool operator==(const Bytes& other) const{
        if(this==&other) return true;
        if(size!=other.size) return false;
        for(size_t i=0;i<size;i++){
            if( data[i]!=other.data[i]) return false;
        }
        return true;
    }
    bool operator!=(const Bytes& other) const{
        return !( *this==other);
    }
    operator std::string () const {
        return {(char *)data,size};
    }
    std::string hexStr() const {
        std::stringstream ss;
        for(size_t i=0;i<size;i++){
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)(((uint8_t*)data)[i]) << ' ';
        }
        return ss.str();
    }
    ~Bytes(){
        delete[] (char *)data;
        size=0;
    }
};

class BytesWriter;

class BytesReader {
    friend size_t copy(BytesWriter& bw,BytesReader& br,size_t n);
private:
    uint8_t * p;
    size_t size;
    size_t rp;
public:
    BytesReader():p(nullptr),size(0),rp(0){}
    BytesReader(const Bytes& b) : p(b.data),size(b.size),rp(0){}
    BytesReader(void *p_,size_t size_):p((uint8_t*)p_) , size(size_),rp(0){}

    template<typename T>
    T readNum(int endian=BIG_ENDIAN){
        T num;
        memcpy(&num,p+rp, sizeof(num));
        rp+=sizeof(num);
        if(endian==BIG_ENDIAN) reverseBytes(&num,sizeof(num));
        return num;
    }
    size_t readBytes(void* dst,size_t len){
        if(len>size-rp) len=size-rp;
        memcpy(dst,p+rp,len);
        rp+=len;
        return len;
    }
    Bytes readBytes(size_t len){
        if(len>size-rp) len=size-rp;
        Bytes bytes(p+rp,len);
        rp+=len;
        return std::move(bytes);
    };
    BytesReader& jmp(size_t pos=0){
        if(pos>=size) pos=size-1;
        rp=pos;
        return *this;
    }
    size_t readableBytes() const{return size-rp;}
    size_t readn() const{return rp;}
};

class BytesWriter{
    friend size_t copy(BytesWriter& bw,BytesReader& br,size_t n);
private:
    uint8_t * p;
    size_t size;
    size_t wp;
public:
    BytesWriter():p(nullptr),size(0),wp(0){}
    BytesWriter(const Bytes& b) : p(b.data),size(b.size),wp(0){}
    BytesWriter(void *p_,size_t size_):p((uint8_t*)p_) , size(size_),wp(0){}

    template<typename T>
    bool writeNum(T num,int endian=BIG_ENDIAN){
        if(size-wp<sizeof(num)) return false;
        if(endian==BIG_ENDIAN) reverseBytes(&num, sizeof(num));
        memcpy(p+wp,&num,sizeof(num));
        wp+=sizeof (num);
        return true;
    }
    size_t writeBytes(const void *src,size_t len){
        if(len>size-wp) len=size-wp;
        memcpy(p+wp,src,len);
        wp+=len;
        return len;
    }
    size_t writeBytes(const Bytes& bytes){
        size_t len = bytes.size > size-wp ? size-wp : bytes.size;
        memcpy(p+wp,bytes.data,len);
        wp+=len;
        return len;
    }
    BytesWriter& jmp(size_t pos=0){
        if(pos>=size) pos=size-1;
        wp=pos;
        return *this;
    }
    size_t writableBytes()  const {return size-wp;}
    size_t writen() const {return wp;}
};

#endif
