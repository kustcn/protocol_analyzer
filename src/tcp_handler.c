#include "../include/common.h"
#include "tcp_handler.h"
#include <stdio.h>
#include <string.h>

int parse_tcp(const uint8_t *packet, int length, TCPHeader *tcp) {
    if (length < 20) {
        return -1;
    }

    tcp->src_port = (packet[0] << 8) | packet[1];
    tcp->dst_port = (packet[2] << 8) | packet[3];

    tcp->seq_num = ((uint32_t)packet[4] << 24) |
                   ((uint32_t)packet[5] << 16) |
                   ((uint32_t)packet[6] << 8) |
                   ((uint32_t)packet[7]);

    tcp->ack_num = ((uint32_t)packet[8] << 24) |
                   ((uint32_t)packet[9] << 16) |
                   ((uint32_t)packet[10] << 8) |
                   ((uint32_t)packet[11]);

    tcp->data_offset = (packet[12] & 0xf0) >> 4;
    tcp->flags = packet[13];

    tcp->window = (packet[14] << 8) | packet[15];
    tcp->checksum = (packet[16] << 8) | packet[17];
    tcp->urgent = (packet[18] << 8) | packet[19];

    int header_len = tcp->data_offset * 4;
    return header_len;
}

void print_tcp_info(const TCPHeader *tcp, const char *src_ip, const char *dst_ip) {
    printf("[TCP] 源端口: %d -> 目标端口: %d\n", tcp->src_port, tcp->dst_port);
    printf("     序列号: %u, 确认号: %u\n", tcp->seq_num, tcp->ack_num);
    printf("     数据偏移: %d字节, 窗口大小: %d\n", tcp->data_offset * 4, tcp->window);
    printf("     标志位: ");

    int first = 1;
    if (tcp->flags & TCP_FLAG_SYN) {
        printf("SYN");
        first = 0;
    }
    if (tcp->flags & TCP_FLAG_ACK) {
        printf("%sACK", first ? "" : "+");
        first = 0;
    }
    if (tcp->flags & TCP_FLAG_FIN) {
        printf("%sFIN", first ? "" : "+");
        first = 0;
    }
    if (tcp->flags & TCP_FLAG_RST) {
        printf("%sRST", first ? "" : "+");
        first = 0;
    }
    if (tcp->flags & TCP_FLAG_PSH) {
        printf("%sPSH", first ? "" : "+");
        first = 0;
    }
    if (tcp->flags & TCP_FLAG_URG) {
        printf("%sURG", first ? "" : "+");
    }

    if (first) {
        printf("无");
    }
    printf("\n");

    const char *handshake_status = get_tcp_handshake_status(tcp, tcp->seq_num, tcp->ack_num);
    if (handshake_status) {
        printf("     >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
        printf("     >>> 三次握手状态: %s <<<\n", handshake_status);
        printf("     >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    }
}

const char* get_tcp_handshake_status(const TCPHeader *tcp, uint32_t seq, uint32_t ack) {
    int syn = (tcp->flags & TCP_FLAG_SYN) != 0;
    int ack_flag = (tcp->flags & TCP_FLAG_ACK) != 0;
    int fin = (tcp->flags & TCP_FLAG_FIN) != 0;
    int rst = (tcp->flags & TCP_FLAG_RST) != 0;

    if (rst) {
        return "连接重置 (RST)";
    }

    if (fin) {
        return "连接关闭 (FIN)";
    }

    if (syn && !ack_flag) {
        return "第一次握手: SYN (客户端请求建立连接)";
    }

    if (syn && ack_flag) {
        return "第二次握手: SYN+ACK (服务器确认并请求建立连接)";
    }

    if (ack_flag && !syn && !fin) {
        return "第三次握手: ACK (客户端确认, 连接建立完成)";
    }

    if (ack_flag && (tcp->flags & TCP_FLAG_PSH)) {
        return "连接已建立, 数据传输中 (PSH+ACK)";
    }

    if (ack_flag) {
        return "连接已建立 (ACK)";
    }

    return NULL;
}
