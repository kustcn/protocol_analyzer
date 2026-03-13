#include "../include/common.h"
#include "udp_handler.h"
#include <stdio.h>

int parse_udp(const uint8_t *packet, int length, UDPHeader *udp) {
    if (length < 8) {
        return -1;
    }

    udp->src_port = (packet[0] << 8) | packet[1];
    udp->dst_port = (packet[2] << 8) | packet[3];
    udp->length = (packet[4] << 8) | packet[5];
    udp->checksum = (packet[6] << 8) | packet[7];

    return 8;
}

void print_udp_info(const UDPHeader *udp) {
    printf("[UDP] 源端口: %d -> 目标端口: %d\n", udp->src_port, udp->dst_port);
    printf("     UDP长度: %d字节, 校验和: 0x%04x\n", udp->length, udp->checksum);
}
