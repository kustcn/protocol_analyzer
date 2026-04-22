#ifndef IPV6_PARSE_H
#define IPV6_PARSE_H

#include <stdint.h>

#define IPV6_HEADER_LEN 40
#define IPV6_ADDR_LEN 16

typedef struct {
    uint8_t  version;
    uint8_t  traffic_class;
    uint8_t  flow_label[3];
    uint16_t payload_length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src_ip[IPV6_ADDR_LEN];
    uint8_t  dst_ip[IPV6_ADDR_LEN];
} IPv6Header;

int parse_ipv6(const uint8_t *packet, int length, IPv6Header *ip);
void print_ipv6_info(const IPv6Header *ip);

#endif
