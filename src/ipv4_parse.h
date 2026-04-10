#ifndef IPV4_PARSE_H
#define IPV4_PARSE_H

#include <stdint.h>
#include <netinet/ip.h>

typedef struct {
    uint8_t  version;
    uint8_t  ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_offset;
    uint8_t  flags;
    uint8_t  reserved;
    uint8_t  df;
    uint8_t  mf;
    uint16_t fragment_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} IPv4Header;

int parse_ipv4(const uint8_t *packet, int length, IPv4Header *ip);
void print_ipv4_info(const IPv4Header *ip);

#endif
