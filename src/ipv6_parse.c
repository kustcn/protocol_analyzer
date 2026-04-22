#include "../include/common.h"
#include "ipv6_parse.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

int parse_ipv6(const uint8_t *packet, int length, IPv6Header *ip) {
    if (length < IPV6_HEADER_LEN) {
        return -1;
    }

    uint8_t first_byte = packet[0];
    ip->version = (first_byte & 0xf0) >> 4;
    ip->traffic_class = first_byte & 0x0f;
    
    // Extract traffic class and flow label from bytes 1-3
    // Traffic class upper 4 bits are in byte 0 (already extracted)
    // Traffic class lower 4 bits + flow label (20 bits) are in bytes 1-3
    ip->traffic_class |= (packet[1] & 0xf0) << 4;
    ip->flow_label[0] = packet[1] & 0x0f;
    ip->flow_label[1] = packet[2];
    ip->flow_label[2] = packet[3];
    
    ip->payload_length = (packet[4] << 8) | packet[5];
    ip->next_header = packet[6];
    ip->hop_limit = packet[7];

    // Copy source and destination IPv6 addresses (16 bytes each)
    memcpy(ip->src_ip, packet + 8, IPV6_ADDR_LEN);
    memcpy(ip->dst_ip, packet + 24, IPV6_ADDR_LEN);

    return IPV6_HEADER_LEN;
}

void print_ipv6_info(const IPv6Header *ip) {
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    struct in6_addr src_addr, dst_addr;
    memcpy(&src_addr.s6_addr, ip->src_ip, IPV6_ADDR_LEN);
    memcpy(&dst_addr.s6_addr, ip->dst_ip, IPV6_ADDR_LEN);

    inet_ntop(AF_INET6, &src_addr, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &dst_addr, dst_ip, INET6_ADDRSTRLEN);

    printf("[IPv6] 源IP: %s\n", src_ip);
    printf("        目标IP: %s\n", dst_ip);
    printf("        版本: %d, 流量类别: 0x%02x, 流标签: 0x%06x\n",
           ip->version, ip->traffic_class,
           (ip->flow_label[0] << 16) | (ip->flow_label[1] << 8) | ip->flow_label[2]);
    printf("        载荷长度: %d字节, 下一头部: %d (", 
           ip->payload_length, ip->next_header);

    switch (ip->next_header) {
        case IP_PROTO_TCP:
            printf("TCP");
            break;
        case IP_PROTO_UDP:
            printf("UDP");
            break;
        case IP_PROTO_ICMP:
            printf("ICMPv6");
            break;
        default:
            printf("未知 (%d)", ip->next_header);
            break;
    }
    printf("), 跳数限制: %d\n", ip->hop_limit);
}

