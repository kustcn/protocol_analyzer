#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <pcap.h>

typedef void (*PacketHandler)(const uint8_t *packet, int length, 
                              const struct pcap_pkthdr *hdr, void *user_data);

int init_pcap(const char *device, const char *filter_exp, int timeout, pcap_t **handle);
void packet_loop(pcap_t *handle, int count, PacketHandler handler, void *user_data);

void parse_packet(const uint8_t *packet, int length, const struct pcap_pkthdr *hdr, void *user_data);

#endif
