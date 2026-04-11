#ifndef ICMP_HANDLER_H
#define ICMP_HANDLER_H

#include <stdint.h>

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    union {
        struct {
            uint16_t id;
            uint16_t sequence;
        } echo;
        struct {
            uint8_t  unused[4];
        } dest_unreachable;
        struct {
            uint32_t gateway;
        } redirect;
        struct {
            uint16_t unused;
            uint16_t mtu;
        } fragment_needed;
    } un;
} ICMPHeader;

// ICMP Type definitions
#define ICMP_TYPE_ECHO_REPLY        0
#define ICMP_TYPE_DEST_UNREACHABLE  3
#define ICMP_TYPE_SOURCE_QUENCH     4
#define ICMP_TYPE_REDIRECT          5
#define ICMP_TYPE_ECHO_REQUEST      8
#define ICMP_TYPE_TIME_EXCEEDED     11
#define ICMP_TYPE_PARAM_PROBLEM     12
#define ICMP_TYPE_TIMESTAMP_REQUEST 13
#define ICMP_TYPE_TIMESTAMP_REPLY   14

// ICMP Code for Destination Unreachable
#define ICMP_CODE_NET_UNREACHABLE   0
#define ICMP_CODE_HOST_UNREACHABLE  1
#define ICMP_CODE_PROT_UNREACHABLE  2
#define ICMP_CODE_PORT_UNREACHABLE  3
#define ICMP_CODE_FRAG_NEEDED       4
#define ICMP_CODE_SRC_FAILED        5

const char* get_icmp_type_name(uint8_t type);
const char* get_icmp_code_name(uint8_t type, uint8_t code);

int parse_icmp(const uint8_t *packet, int length, ICMPHeader *icmp);
void print_icmp_info(const ICMPHeader *icmp, const uint8_t *payload, int payload_len);

#endif
