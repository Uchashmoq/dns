cmake_minimum_required(VERSION 3.24)
project(dns)

set(CMAKE_CXX_STANDARD 17)

add_executable(dns main.cpp lib/Bytes.hpp protocol/Dns.h protocol/Dns.cpp tests.hpp net/udp.cpp net/udp.h net/net.h net/net.cpp net/DnsChannel.cpp net/DnsChannel.h lib/aes.hpp lib/aes.h lib/aes.c protocol/base36.cpp protocol/base36.h protocol/Layer.cpp protocol/Layer.h lib/BlockingQueue.hpp protocol/Packet.cpp protocol/Packet.h lib/Log.h lib/bytes.cpp lib/Log.cpp lib/strings.h lib/strings.cpp)

if(WIN32)
    target_link_libraries(dns PRIVATE ws2_32)
endif()