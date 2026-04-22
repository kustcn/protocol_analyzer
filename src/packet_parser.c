#include "../include/common.h"
#include "packet_parser.h"
#include "ethernet_parse.h"
#include "ipv4_parse.h"
#include "ipv6_parse.h"
#include "tcp_handler.h"
#include "udp_handler.h"
#include "icmp_handler.h"
#include "logger.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

int init_pcap(const char *device, const char *filter_exp, int timeout, pcap_t **handle) {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;
    struct bpf_program fp;

    LOG_DEBUG("Initializing pcap - device: %s, filter: %s", 
              device ? device : "auto", filter_exp ? filter_exp : "none");

    if (device == NULL) {
        device = pcap_lookupdev(errbuf);
        if (device == NULL) {
            fprintf(stderr, "无法找到网络设备: %s\n", errbuf);
            return -1;
        }
        LOG_INFO("使用默认设备: %s", device);
    }

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        LOG_ERROR("获取网络设备信息失败: %s", errbuf);
        net = 0;
        mask = 0;
    }

    *handle = pcap_open_live(device, SNAPLEN, 1, timeout, errbuf);
    if (*handle == NULL) {
        LOG_ERROR("打开设备失败: %s", errbuf);
        return -1;
    }

    if (pcap_datalink(*handle) != DLT_EN10MB) {
        LOG_WARN("警告: 设备不是以太网");
    }

    if (filter_exp != NULL && strlen(filter_exp) > 0) {
        if (pcap_compile(*handle, &fp, filter_exp, 0, net) == -1) {
            LOG_ERROR("编译过滤器失败: %s", pcap_geterr(*handle));
            return -1;
        }

        if (pcap_setfilter(*handle, &fp) == -1) {
            LOG_ERROR("设置过滤器失败: %s", pcap_geterr(*handle));
            pcap_freecode(&fp);
            return -1;
        }

        pcap_freecode(&fp);
        LOG_INFO("过滤器已应用: %s", filter_exp);
    }

    return 0;
}

void packet_loop(pcap_t *handle, int count, PacketHandler handler, void *user_data) {
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int result;

    LOG_INFO("\n开始捕获数据包 (Ctrl+C 停止)...");
    print_separator();

    if (count > 0) {
        for (int i = 0; i < count; i++) {
            result = pcap_next_ex(handle, &header, &packet);
            if (result == 1) {
                handler(packet, header->len, header, user_data);
            } else if (result == 0) {
                continue;
            } else if (result == -1) {
                LOG_ERROR("捕获错误: %s", pcap_geterr(handle));
                break;
            } else if (result == -2) {
                LOG_INFO("捕获结束 (达到数据包数量限制)");
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
                LOG_ERROR("捕获错误: %s", pcap_geterr(handle));
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

    LOG_DEBUG("Packet received - length: %d, caplen: %d", hdr->len, hdr->caplen);

    print_timestamp(hdr);
    print_separator();

    EthernetHeader eth;
    int eth_len = parse_ethernet(packet, length, &eth);
    if (eth_len < 0) {
        LOG_WARN("数据包太短, 无法解析以太网头部");
        return;
    }

    print_ethernet_info(&eth);

    if (eth.ether_type == ETH_TYPE_IPV4) {
        const uint8_t *ip_packet = packet + eth_len;
        int ip_len = length - eth_len;

        IPv4Header ip;
        int header_len = parse_ipv4(ip_packet, ip_len, &ip);
        if (header_len < 0) {
            LOG_WARN("IP头部解析失败");
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
                LOG_WARN("TCP header parse failed");
                printf("TCP头部解析失败\n");
                return;
            }

            print_tcp_info(&tcp, src_ip, dst_ip);
            LOG_INFO("TCP: %s:%d -> %s:%d, flags=0x%02x", 
                     src_ip, tcp.src_port, dst_ip, tcp.dst_port, tcp.flags);

        } else if (ip.protocol == IP_PROTO_UDP) {
            UDPHeader udp;
            int udp_len = parse_udp(transport_packet, transport_len, &udp);
            if (udp_len < 0) {
                LOG_WARN("UDP header parse failed");
                printf("UDP头部解析失败\n");
                return;
            }

            print_udp_info(&udp);
            LOG_INFO("UDP: %d -> %d, length=%d", udp.src_port, udp.dst_port, udp.length);

        } else if (ip.protocol == IP_PROTO_ICMP) {
            ICMPHeader icmp;
            int icmp_len = parse_icmp(transport_packet, transport_len, &icmp);
            if (icmp_len < 0) {
                LOG_WARN("ICMP header parse failed");
                printf("ICMP头部解析失败\n");
                return;
            }

            print_icmp_info(&icmp, transport_packet + icmp_len, transport_len - icmp_len);
            LOG_INFO("ICMP: type=%d, code=%d", icmp.type, icmp.code);

        } else {
            LOG_DEBUG("Unsupported protocol: %d", ip.protocol);
            printf("     不支持的传输层协议: %d\n", ip.protocol);
        }

    } else if (eth.ether_type == ETH_TYPE_IPV6) {
        const uint8_t *ip_packet = packet + eth_len;
        int ip_len = length - eth_len;

        IPv6Header ip;
        int header_len = parse_ipv6(ip_packet, ip_len, &ip);
        if (header_len < 0) {
            LOG_WARN("IPv6头部解析失败");
            return;
        }

        print_ipv6_info(&ip);

        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        struct in6_addr src_addr, dst_addr;
        memcpy(&src_addr.s6_addr, ip.src_ip, IPV6_ADDR_LEN);
        memcpy(&dst_addr.s6_addr, ip.dst_ip, IPV6_ADDR_LEN);
        inet_ntop(AF_INET6, &src_addr, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &dst_addr, dst_ip, INET6_ADDRSTRLEN);

        const uint8_t *transport_packet = ip_packet + header_len;
        int transport_len = ip_len - header_len;

        if (ip.next_header == IP_PROTO_TCP) {
            TCPHeader tcp;
            int tcp_len = parse_tcp(transport_packet, transport_len, &tcp);
            if (tcp_len < 0) {
                LOG_WARN("TCP header parse failed");
                printf("TCP头部解析失败\n");
                return;
            }

            print_tcp_info(&tcp, src_ip, dst_ip);
            LOG_INFO("TCP: %s:%d -> %s:%d, flags=0x%02x", 
                     src_ip, tcp.src_port, dst_ip, tcp.dst_port, tcp.flags);

        } else if (ip.next_header == IP_PROTO_UDP) {
            UDPHeader udp;
            int udp_len = parse_udp(transport_packet, transport_len, &udp);
            if (udp_len < 0) {
                LOG_WARN("UDP header parse failed");
                printf("UDP头部解析失败\n");
                return;
            }

            print_udp_info(&udp);
            LOG_INFO("UDP: %d -> %d, length=%d", udp.src_port, udp.dst_port, udp.length);

        } else if (ip.next_header == IP_PROTO_ICMPV6) {
            // IPv6 uses ICMPv6 (type 58), which has the same structure as ICMP
            ICMPHeader icmp;
            int icmp_len = parse_icmp(transport_packet, transport_len, &icmp);
            if (icmp_len < 0) {
                LOG_WARN("ICMPv6 header parse failed");
                printf("ICMPv6头部解析失败\n");
                return;
            }

            print_icmp_info(&icmp, transport_packet + icmp_len, transport_len - icmp_len);
            LOG_INFO("ICMPv6: type=%d, code=%d", icmp.type, icmp.code);

        } else {
            LOG_DEBUG("Unsupported protocol: %d", ip.next_header);
            printf("     不支持的传输层协议: %d\n", ip.next_header);
        }

    } else {
        LOG_WARN("只支持IPv4和IPv6协议");
        print_separator();
        printf("\n");
        return;
    }

    print_separator();
    printf("\n");
}
