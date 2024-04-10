## 协议

### Dns 结构体 

```c++
//protocol/dns.h
struct Query {
    //携带dns隧道数据，从客户端发往服务器
    std::vector<Bytes> question;
    uint16_t queryType;
    uint16_t queryClass;
};
struct Answer {
    std::vector<Bytes> name;
    uint16_t ansType;
    uint16_t ansClass;
    uint32_t ttl;
    uint16_t dataLen;
    
    //携带dns隧道数据，从服务器发往客户端
    std::vector<Bytes> data;
};
struct Nameserver {
    std::vector<Bytes> name;
    uint16_t nsType;
    uint16_t nsClass;
    uint32_t ttl;
    uint16_t dataLen;
    Bytes data;
};
struct Additional{
    std::vector<Bytes> name;
    uint16_t addType;
    uint16_t addClass;
    uint32_t ttl;
    uint16_t dataLen;
    
    //携带dns隧道数据，从服务器发往客户端
    std::vector<Bytes> data;
};
struct Dns {
    uint16_t transactionId;
    uint16_t flags;
    uint16_t questions;
    uint16_t answerRRs;
    uint16_t authorityRRs;
    uint16_t additionalRRs;
    std::vector<Query> queries;
    std::vector<Answer> answers;
    std::vector<Nameserver> nameservers;
    std::vector<Additional> additions;
};
```

### Packet结构体

```c++
struct Packet {
    SA_IN addr;//数据包源IP地址
    uint16_t sessionId;
    uint16_t groupId;
    uint16_t dataId;
    uint8_t type;
    Bytes data;
};
```

由于dns协议基于udp协议，会出现丢包，乱序等问题，因此需要对数据包进行处理。

sessionId：与tcp类似，这里定义的dnssocket协议需要进行连接才能通信，sessionId用于识别不同的会话。groupId用于标识不同的数据分组，例如我要发送hello和world，这两段数据便会拥有一个递增的groupId，当数据接收顺序错误时，按groupId进行排序。dataId由于单个dns请求能够搭载的数据量有限，所以可能会对一个分组里面的数据分段发送，例如先发送he在发送llo，这两个数据会有一个递增的dataId，在同一个分组内，会先按dataId进行排序，组成一个完整的分组。type：标识数据的类型，正在制定...

### Packet与Dns的转换

