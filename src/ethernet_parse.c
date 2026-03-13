#include "../include/common.h"
#include "ethernet_parse.h"
#include "utils.h"
#include <stdio.h>

#define ETH_HEADER_LEN 14

int parse_ethernet(const uint8_t *packet, int length, EthernetHeader *eth) {
    if (length < ETH_HEADER_LEN) {
        return -1;
    }

    memcpy(eth->dhost, packet, 6);
    memcpy(eth->shost, packet + 6, 6);
    eth->ether_type = (packet[12] << 8) | packet[13];

    return ETH_HEADER_LEN;
}

void print_ethernet_info(const EthernetHeader *eth) {
    char src_mac[18];
    char dst_mac[18];

    format_mac(eth->shost, src_mac);
    format_mac(eth->dhost, dst_mac);

    printf("[以太网] 源MAC: %s -> 目标MAC: %s\n", src_mac, dst_mac);

    switch (eth->ether_type) {
        case ETH_TYPE_IPV4:
            printf("         上层协议: IPv4 (0x%04x)\n", eth->ether_type);
            break;
        case ETH_TYPE_IPV6:
            printf("         上层协议: IPv6 (0x%04x)\n", eth->ether_type);
            break;
        case ETH_TYPE_ARP:
            printf("         上层协议: ARP (0x%04x)\n", eth->ether_type);
            break;
        default:
            printf("         上层协议: 未知 (0x%04x)\n", eth->ether_type);
            break;
    }
}
