#include "../include/common.h"
#include "packet_parser.h"
#include "ethernet_parse.h"
#include "ipv4_parse.h"
#include "tcp_handler.h"
#include "udp_handler.h"
#include "icmp_handler.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

int init_pcap(const char *device, const char *filter_exp, int timeout, pcap_t **handle) {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;
    struct bpf_program fp;

    if (device == NULL) {
        device = pcap_lookupdev(errbuf);
        if (device == NULL) {
            fprintf(stderr, "无法找到网络设备: %s\n", errbuf);
            return -1;
        }
        printf("使用默认设备: %s\n", device);
    }

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "获取网络设备信息失败: %s\n", errbuf);
        net = 0;
        mask = 0;
    }

    *handle = pcap_open_live(device, SNAPLEN, 1, timeout, errbuf);
    if (*handle == NULL) {
        fprintf(stderr, "打开设备失败: %s\n", errbuf);
        return -1;
    }

    if (pcap_datalink(*handle) != DLT_EN10MB) {
        fprintf(stderr, "警告: 设备不是以太网\n");
    }

    if (filter_exp != NULL && strlen(filter_exp) > 0) {
        if (pcap_compile(*handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "编译过滤器失败: %s\n", pcap_geterr(*handle));
            return -1;
        }

        if (pcap_setfilter(*handle, &fp) == -1) {
            fprintf(stderr, "设置过滤器失败: %s\n", pcap_geterr(*handle));
            pcap_freecode(&fp);
            return -1;
        }

        pcap_freecode(&fp);
        printf("过滤器已应用: %s\n", filter_exp);
    }

    return 0;
}

void packet_loop(pcap_t *handle, int count, PacketHandler handler, void *user_data) {
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int result;

    printf("\n开始捕获数据包 (Ctrl+C 停止)...\n");
    print_separator();

    if (count > 0) {
        for (int i = 0; i < count; i++) {
            result = pcap_next_ex(handle, &header, &packet);
            if (result == 1) {
                handler(packet, header->len, header, user_data);
            } else if (result == 0) {
                continue;
            } else if (result == -1) {
                fprintf(stderr, "捕获错误: %s\n", pcap_geterr(handle));
                break;
            } else if (result == -2) {
                printf("捕获结束 (达到数据包数量限制)\n");
                break;
            }
        }
    } else {
        int packet_count = 0;
        while (1) {
            result = pcap_next_ex(handle, &header, &packet);
            if (result == 1) {
                packet_count++;
                handler(packet, header->len, header, user_data);
            } else if (result == -1) {
                fprintf(stderr, "捕获错误: %s\n", pcap_geterr(handle));
                break;
            } else if (result == -2) {
                break;
            }
        }
        printf("\n共捕获 %d 个数据包\n", packet_count);
    }
}

void parse_packet(const uint8_t *packet, int length, const struct pcap_pkthdr *hdr, void *user_data) {
    (void)user_data;

    print_timestamp(hdr);
    print_separator();

    EthernetHeader eth;
    int eth_len = parse_ethernet(packet, length, &eth);
    if (eth_len < 0) {
        printf("数据包太短, 无法解析以太网头部\n");
        return;
    }

    print_ethernet_info(&eth);

    if (eth.ether_type != ETH_TYPE_IPV4) {
        printf("只支持IPv4协议\n");
        print_separator();
        printf("\n");
        return;
    }

    const uint8_t *ip_packet = packet + eth_len;
    int ip_len = length - eth_len;

    IPv4Header ip;
    int header_len = parse_ipv4(ip_packet, ip_len, &ip);
    if (header_len < 0) {
        printf("IP头部解析失败\n");
        return;
    }

    print_ipv4_info(&ip);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    format_ip(ip.src_ip, src_ip);
    format_ip(ip.dst_ip, dst_ip);

    const uint8_t *transport_packet = ip_packet + header_len;
    int transport_len = ip_len - header_len;

    if (ip.protocol == IP_PROTO_TCP) {
        TCPHeader tcp;
        int tcp_len = parse_tcp(transport_packet, transport_len, &tcp);
        if (tcp_len < 0) {
            printf("TCP头部解析失败\n");
            return;
        }

        print_tcp_info(&tcp, src_ip, dst_ip);

    } else if (ip.protocol == IP_PROTO_UDP) {
        UDPHeader udp;
        int udp_len = parse_udp(transport_packet, transport_len, &udp);
        if (udp_len < 0) {
            printf("UDP头部解析失败\n");
            return;
        }

        print_udp_info(&udp);

    } else if (ip.protocol == IP_PROTO_ICMP) {
        ICMPHeader icmp;
        int icmp_len = parse_icmp(transport_packet, transport_len, &icmp);
        if (icmp_len < 0) {
            printf("ICMP头部解析失败\n");
            return;
        }

        print_icmp_info(&icmp, transport_packet + icmp_len, transport_len - icmp_len);

    } else {
        printf("     不支持的传输层协议: %d\n", ip.protocol);
    }

    print_separator();
    printf("\n");
}
