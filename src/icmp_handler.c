#include "../include/common.h"
#include "icmp_handler.h"
#include <stdio.h>

const char* get_icmp_type_name(uint8_t type) {
    switch (type) {
        case ICMP_TYPE_ECHO_REPLY:        return "Echo Reply";
        case ICMP_TYPE_DEST_UNREACHABLE:  return "Destination Unreachable";
        case ICMP_TYPE_SOURCE_QUENCH:     return "Source Quench";
        case ICMP_TYPE_REDIRECT:          return "Redirect";
        case ICMP_TYPE_ECHO_REQUEST:      return "Echo Request";
        case ICMP_TYPE_TIME_EXCEEDED:     return "Time Exceeded";
        case ICMP_TYPE_PARAM_PROBLEM:     return "Parameter Problem";
        case ICMP_TYPE_TIMESTAMP_REQUEST: return "Timestamp Request";
        case ICMP_TYPE_TIMESTAMP_REPLY:   return "Timestamp Reply";
        default:                          return "Unknown";
    }
}

const char* get_icmp_code_name(uint8_t type, uint8_t code) {
    if (type == ICMP_TYPE_DEST_UNREACHABLE) {
        switch (code) {
            case ICMP_CODE_NET_UNREACHABLE:  return "Network Unreachable";
            case ICMP_CODE_HOST_UNREACHABLE: return "Host Unreachable";
            case ICMP_CODE_PROT_UNREACHABLE: return "Protocol Unreachable";
            case ICMP_CODE_PORT_UNREACHABLE: return "Port Unreachable";
            case ICMP_CODE_FRAG_NEEDED:      return "Fragmentation Needed";
            case ICMP_CODE_SRC_FAILED:       return "Source Route Failed";
            default:                         return "Unknown";
        }
    } else if (type == ICMP_TYPE_TIME_EXCEEDED) {
        switch (code) {
            case 0: return "TTL Expired in Transit";
            case 1: return "Fragment Reassembly Time Exceeded";
            default: return "Unknown";
        }
    }
    return "";
}

int parse_icmp(const uint8_t *packet, int length, ICMPHeader *icmp) {
    if (length < 4) {
        return -1;
    }

    icmp->type = packet[0];
    icmp->code = packet[1];
    icmp->checksum = (packet[2] << 8) | packet[3];

    // Parse additional fields based on type
    if (icmp->type == ICMP_TYPE_ECHO_REQUEST || 
        icmp->type == ICMP_TYPE_ECHO_REPLY ||
        icmp->type == ICMP_TYPE_TIMESTAMP_REQUEST ||
        icmp->type == ICMP_TYPE_TIMESTAMP_REPLY) {
        
        if (length >= 8) {
            icmp->un.echo.id = (packet[4] << 8) | packet[5];
            icmp->un.echo.sequence = (packet[6] << 8) | packet[7];
        }
    }

    return 8; // Minimum ICMP header size
}

void print_icmp_info(const ICMPHeader *icmp, const uint8_t *payload, int payload_len) {
    (void)payload;
    (void)payload_len;

    printf("[ICMP] 类型: %s (%d), 代码: %s (%d)\n",
           get_icmp_type_name(icmp->type), icmp->type,
           get_icmp_code_name(icmp->type, icmp->code), icmp->code);
    printf("       校验和: 0x%04x\n", icmp->checksum);

    // Print type-specific information
    if (icmp->type == ICMP_TYPE_ECHO_REQUEST || 
        icmp->type == ICMP_TYPE_ECHO_REPLY) {
        printf("       标识符: 0x%04x, 序列号: %u\n",
               icmp->un.echo.id, icmp->un.echo.sequence);
    } else if (icmp->type == ICMP_TYPE_DEST_UNREACHABLE) {
        printf("       目标不可达: %s\n", get_icmp_code_name(icmp->type, icmp->code));
    } else if (icmp->type == ICMP_TYPE_TIME_EXCEEDED) {
        printf("       TTL超时: %s\n", get_icmp_code_name(icmp->type, icmp->code));
    }
}
