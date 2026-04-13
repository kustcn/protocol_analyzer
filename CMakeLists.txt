cmake_minimum_required(VERSION 3.10)
project(ProtocolAnalyzer VERSION 1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -g")

find_package(Threads REQUIRED)

find_library(Pcap_LIBRARY pcap REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include)

set(SOURCES
    src/main.c
    src/packet_parser.c
    src/tcp_handler.c
    src/udp_handler.c
    src/icmp_handler.c
    src/ethernet_parse.c
    src/ipv4_parse.c
    src/utils.c
    src/logger.c
)

set(HEADERS
    include/common.h
    src/packet_parser.h
    src/tcp_handler.h
    src/udp_handler.h
    src/icmp_handler.h
    src/ethernet_parse.h
    src/ipv4_parse.h
    src/utils.h
    src/logger.h
)

add_executable(protocol_analyzer ${SOURCES} ${HEADERS})

target_link_libraries(protocol_analyzer 
    Threads::Threads 
    ${Pcap_LIBRARY}
)

target_include_directories(protocol_analyzer PRIVATE 
    ${CMAKE_SOURCE_DIR}/src
)
