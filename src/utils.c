#include "../include/common.h"
#include "utils.h"
#include <stdio.h>
#include <arpa/inet.h>

void hex_dump(const uint8_t *data, int length) {
    printf("    0000: ");
    for (int i = 0; i < length; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 && i < length - 1) {
            printf("\n    %04x: ", i + 1);
        }
    }
    printf("\n");
}

void format_mac(const uint8_t *mac, char *buffer) {
    snprintf(buffer, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void format_ip(uint32_t ip, char *buffer) {
    struct in_addr addr;
    addr.s_addr = ip;
    snprintf(buffer, INET_ADDRSTRLEN, "%s", inet_ntoa(addr));
}
