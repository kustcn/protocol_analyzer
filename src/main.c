#include "../include/common.h"
#include "packet_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

void print_usage(const char *program_name) {
    printf("用法: %s [选项]\n", program_name);
    printf("选项:\n");
    printf("  -i, --interface <设备>   指定网络接口 (如 eth0, en0)\n");
    printf("  -f, --filter <过滤器>    BPF过滤器表达式 (如 'tcp', 'udp', 'port 80')\n");
    printf("  -c, --count <数量>       捕获数据包数量 (默认无限)\n");
    printf("  -t, --timeout <毫秒>     超时时间 (默认1000ms)\n");
    printf("  -v, --verbose            详细输出模式\n");
    printf("  -h, --help               显示此帮助信息\n");
    printf("\n示例:\n");
    printf("  %s -i eth0 -c 10              捕获eth0上10个数据包\n", program_name);
    printf("  %s -f 'tcp' -c 5             捕获5个TCP数据包\n", program_name);
    printf("  %s -f 'port 80' -v           捕获HTTP流量并显示详细信息\n", program_name);
    printf("  %s -f 'tcp and port 443'     捕获HTTPS流量\n", program_name);
}

void print_banner(void) {
    printf("============================================================\n");
    printf("         网络协议分析器 - Protocol Analyzer v1.0\n");
    printf("============================================================\n");
    printf("支持协议: Ethernet, IPv4, TCP, UDP\n");
    printf("功能特点:\n");
    printf("  - 详细TCP三次握手识别\n");
    printf("  - BPF过滤器支持\n");
    printf("  - 命令行参数化配置\n");
    printf("============================================================\n\n");
}

void print_separator(void) {
    printf("------------------------------------------------------------\n");
}

void print_timestamp(const struct pcap_pkthdr *hdr) {
    struct tm *ltime = localtime(&hdr->ts.tv_sec);
    char timestr[32];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", ltime);

    int usec = hdr->ts.tv_usec;
    printf("\n>>> 时间: %s.%06d | 长度: %d字节 <<<\n", timestr, usec, hdr->len);
}

int main(int argc, char *argv[]) {
    AppConfig config = {
        .device = NULL,
        .filter_exp = NULL,
        .verbose = 0,
        .count = 0,
        .promiscuous = 1,
        .timeout = 1000
    };

    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"filter",    required_argument, 0, 'f'},
        {"count",     required_argument, 0, 'c'},
        {"timeout",   required_argument, 0, 't'},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "i:f:c:t:vh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                config.device = optarg;
                break;
            case 'f':
                config.filter_exp = optarg;
                break;
            case 'c':
                config.count = atoi(optarg);
                break;
            case 't':
                config.timeout = atoi(optarg);
                break;
            case 'v':
                config.verbose = 1;
                break;
            case 'h':
                print_banner();
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    print_banner();

    pcap_t *handle = NULL;

    if (init_pcap(config.device, config.filter_exp, config.timeout, &handle) < 0) {
        fprintf(stderr, "初始化pcap失败\n");
        return 1;
    }

    printf("捕获配置:\n");
    printf("  设备: %s\n", config.device ? config.device : "自动选择");
    printf("  过滤器: %s\n", config.filter_exp ? config.filter_exp : "无");
    printf("  捕获数量: %s\n", config.count > 0 ? "有限" : "无限");
    printf("  超时: %dms\n", config.timeout);
    printf("\n");

    packet_loop(handle, config.count, parse_packet, NULL);

    pcap_close(handle);
    printf("\n分析完成.\n");

    return 0;
}
