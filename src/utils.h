#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

void hex_dump(const uint8_t *data, int length);
void format_mac(const uint8_t *mac, char *buffer);
void format_ip(uint32_t ip, char *buffer);

#endif
