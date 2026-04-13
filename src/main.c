#include "../include/common.h"
#include "packet_parser.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

void print_usage(const char *program_name) {
    printf("用法: %s [选项]\n", program_name);
    printf("选项:\n");
    printf("  -i, --interface <设备|list> 指定网络接口 (如 eth0, en0) 或 'list' 列出所有接口\n");
    printf("  -f, --filter <过滤器>    BPF过滤器表达式 (如 'tcp', 'udp', 'port 80')\n");
    printf("  -c, --count <数量>       捕获数据包数量 (默认无限)\n");
    printf("  -t, --timeout <毫秒>    超时时间 (默认1000ms)\n");
    printf("  -l, --log-file <文件>    日志文件路径\n");
    printf("  -v, --verbose            详细输出模式\n");
    printf("  -h, --help               显示此帮助信息\n");
    printf("\n示例:\n");
    printf("  %s -i list                  列出所有可用网络接口\n", program_name);
    printf("  %s -i eth0 -c 10            捕获eth0上10个数据包\n", program_name);
    printf("  %s -f 'tcp' -c 5            捕获5个TCP数据包\n", program_name);
    printf("  %s -f 'port 80' -v          捕获HTTP流量并显示详细信息\n", program_name);
    printf("  %s -f 'tcp and port 443'   捕获HTTPS流量\n", program_name);
    printf("  %s -i eth0 -l capture.log  捕获数据包并记录到日志\n", program_name);
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

void list_network_interfaces(void) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    printf("\n可用网络接口:\n");
    print_separator();
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "获取网络接口失败: %s\n", errbuf);
        return;
    }
    
    int if_count = 0;
    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
        printf("  * %s", dev->name);
        
        if (dev->description) {
            printf(" - %s", dev->description);
        }
        printf("\n");
        
        if (dev->addresses) {
            for (pcap_addr_t *addr = dev->addresses; addr != NULL; addr = addr->next) {
                if (addr->addr->sa_family == AF_INET) {
                    char ipstr[INET_ADDRSTRLEN];
                    struct sockaddr_in *sin = (struct sockaddr_in *)addr->addr;
                    inet_ntop(AF_INET, &sin->sin_addr, ipstr, INET_ADDRSTRLEN);
                    printf("    地址: %s\n", ipstr);
                }
            }
        }
        if_count++;
    }
    
    print_separator();
    printf("共找到 %d 个接口\n", if_count);
    
    pcap_freealldevs(alldevs);
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
        .log_file = NULL,
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
        {"log-file",  required_argument, 0, 'l'},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "i:f:c:t:l:vh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                if (strcmp(optarg, "list") == 0) {
                    print_banner();
                    list_network_interfaces();
                    return 0;
                }
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
            case 'l':
                config.log_file = optarg;
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

    // Initialize logger
    if (config.log_file != NULL) {
        if (logger_init(config.log_file, LOG_LEVEL_DEBUG) < 0) {
            LOG_ERROR("初始化日志失败");
            return 1;
        }
        LOG_INFO("Logger initialized: %s", config.log_file);
    }

    pcap_t *handle = NULL;

    if (init_pcap(config.device, config.filter_exp, config.timeout, &handle) < 0) {
        LOG_ERROR("初始化pcap失败");
        logger_close();
        return 1;
    }

    LOG_INFO("捕获配置:");
    LOG_INFO("  设备: %s", config.device ? config.device : "自动选择");
    LOG_INFO("  过滤器: %s", config.filter_exp ? config.filter_exp : "无");
    LOG_INFO("  捕获数量: %s", config.count > 0 ? "有限" : "无限");
    LOG_INFO("  超时: %dms", config.timeout);
    if (config.log_file) {
        LOG_INFO("  日志文件: %s", config.log_file);
    }

    LOG_INFO("Capture started - Device: %s, Filter: %s, Count: %d", 
             config.device ? config.device : "auto",
             config.filter_exp ? config.filter_exp : "none",
             config.count);

    packet_loop(handle, config.count, parse_packet, NULL);

    pcap_close(handle);
    
    LOG_INFO("Capture completed");
    logger_close();
    
    printf("\n分析完成.\n");

    return 0;
}
