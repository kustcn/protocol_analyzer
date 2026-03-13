# PROJECT KNOWLEDGE BASE

## OVERVIEW
C语言网络协议分析器, 基于libpcap捕获数据包, 支持TCP/UDP协议解析和TCP三次握手识别。

## STRUCTURE
```
protocol_analyzer/
├── CMakeLists.txt           # CMake构建配置
├── include/
│   └── common.h            # 通用定义
├── src/
│   ├── main.c              # 入口, CLI参数解析
│   ├── packet_parser.c     # 数据包解析主逻辑
│   ├── ethernet_parse.c    # 以太网帧解析
│   ├── ipv4_parse.c       # IPv4头部解析
│   ├── tcp_handler.c      # TCP协议+三次握手
│   ├── udp_handler.c      # UDP协议解析
│   └── utils.c            # 工具函数
└── build/
    └── protocol_analyzer  # 可执行文件
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| 添加新协议 | src/ | 参考tcp_handler.c模式 |
| 修改CLI | src/main.c | getopt_long参数解析 |
| CMake配置 | CMakeLists.txt | 添加新源文件 |

## CODE MAP
| Symbol | Type | Location | Role |
|--------|------|----------|------|
| parse_packet | function | packet_parser.c | 主解析入口 |
| parse_tcp | function | tcp_handler.c | TCP解析 |
| get_tcp_handshake_status | function | tcp_handler.c | 三次握手识别 |
| parse_udp | function | udp_handler.c | UDP解析 |
| parse_ipv4 | function | ipv4_parse.c | IP解析 |
| parse_ethernet | function | ethernet_parse.c | 以太网解析 |

## CONVENTIONS
- 头文件: `#ifndef Xxx_H` / `#define Xxx_H` / `#endif`
- 解析函数: `parse_xxx(packet, length, &header_struct)` 返回头部字节数
- 打印函数: `print_xxx_info(const xxxHeader *h)` 带下划线命名

## ANTI-PATTERNS (THIS PROJECT)
- 禁止使用 `as any`, `@ts-ignore` (C项目无此风险)
- 禁止空catch块
- 解析函数失败必须返回负值

## COMMANDS
```bash
# 编译
mkdir build && cd build && cmake .. && make

# 捕获数据包
./protocol_analyzer -i eth0 -f 'tcp' -c 10
```

## NOTES
- 需要root权限运行 (libpcap)
- BPF过滤器语法: `tcp`, `udp`, `port 80`, `tcp and port 443`
