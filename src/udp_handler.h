#ifndef UDP_HANDLER_H
#define UDP_HANDLER_H

#include <stdint.h>

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} UDPHeader;

int parse_udp(const uint8_t *packet, int length, UDPHeader *udp);
void print_udp_info(const UDPHeader *udp);

#endif
