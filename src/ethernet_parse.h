#ifndef ETHERNET_PARSE_H
#define ETHERNET_PARSE_H

#include <stdint.h>

typedef struct {
    uint8_t  dhost[6];
    uint8_t  shost[6];
    uint16_t ether_type;
} EthernetHeader;

int parse_ethernet(const uint8_t *packet, int length, EthernetHeader *eth);
void print_ethernet_info(const EthernetHeader *eth);

#endif
