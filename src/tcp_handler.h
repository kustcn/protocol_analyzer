#ifndef TCP_HANDLER_H
#define TCP_HANDLER_H

#include <stdint.h>
#include <netinet/tcp.h>

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} TCPHeader;

typedef enum {
    TCP_STATE_UNKNOWN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_ACK,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT,
    TCP_STATE_CLOSING,
    TCP_STATE_CLOSED
} TCPConnectionState;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    TCPConnectionState state;
    uint32_t seq_num;
    uint32_t ack_num;
    int handshake_complete;
} TCPConnection;

int parse_tcp(const uint8_t *packet, int length, TCPHeader *tcp);
void print_tcp_info(const TCPHeader *tcp, const char *src_ip, const char *dst_ip);
const char* get_tcp_handshake_status(const TCPHeader *tcp, uint32_t seq, uint32_t ack);

#endif
