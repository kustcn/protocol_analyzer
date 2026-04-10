#include "../include/common.h"
#include "ipv4_parse.h"
#include "utils.h"
#include <stdio.h>
#include <netinet/in.h>

int parse_ipv4(const uint8_t *packet, int length, IPv4Header *ip) {
    if (length < 20) {
        return -1;
    }

    ip->version = (packet[0] & 0xf0) >> 4;
    ip->ihl = (packet[0] & 0x0f);
    ip->tos = packet[1];
    ip->total_length = (packet[2] << 8) | packet[3];
    ip->identification = (packet[4] << 8) | packet[5];
    ip->flags_offset = (packet[6] << 8) | packet[7];
    
    // Extract flags and fragment offset from flags_offset field
    // Flags are bits 0-2 of the high byte (bit 15-13 of the 16-bit field)
    ip->reserved = (ip->flags_offset & 0x8000) >> 15;  // Bit 0 (MSB)
    ip->df = (ip->flags_offset & 0x4000) >> 14;        // Bit 1 (DF flag)
    ip->mf = (ip->flags_offset & 0x2000) >> 13;        // Bit 2 (MF flag)
    // Fragment offset is bits 3-15 (lower 13 bits)
    ip->fragment_offset = ip->flags_offset & 0x1fff;
    
    ip->ttl = packet[8];
    ip->protocol = packet[9];
    ip->checksum = (packet[10] << 8) | packet[11];

    memcpy(&ip->src_ip, packet + 12, 4);
    memcpy(&ip->dst_ip, packet + 16, 4);

    int header_len = ip->ihl * 4;
    return header_len;
}

void print_ipv4_info(const IPv4Header *ip) {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    format_ip(ip->src_ip, src_ip);
    format_ip(ip->dst_ip, dst_ip);

    printf("[IP] 源IP: %s -> 目标IP: %s\n", src_ip, dst_ip);

    printf("     版本: %d, 头部长度: %d字节, TOS: 0x%02x\n",
           ip->version, ip->ihl * 4, ip->tos);
    printf("     总长度: %d字节, 标识: 0x%04x\n",
           ip->total_length, ip->identification);
    printf("     标志: DF=%d, MF=%d, 分片偏移: %d\n",
           ip->df, ip->mf, ip->fragment_offset);
    printf("     TTL: %d, 协议: ", ip->ttl);

    switch (ip->protocol) {
        case IP_PROTO_TCP:
            printf("TCP (6)\n");
            break;
        case IP_PROTO_UDP:
            printf("UDP (17)\n");
            break;
        case IP_PROTO_ICMP:
            printf("ICMP (1)\n");
            break;
        default:
            printf("未知 (%d)\n", ip->protocol);
            break;
    }
}
