# CHANGE LOG

## 2026-04-22

Added IPv6 support to protocol analyzer

- Create ipv6_parse.h and ipv6_parse.c for IPv6 protocol handling
- Add IPv6Header struct with version, traffic class, flow label, payload length, next header, hop limit, and source/destination IPv6 addresses
- Implement parse_ipv6() to parse 40-byte IPv6 headers and extract all fields
- Implement print_ipv6_info() to format and display IPv6 information with TCP/UDP/ICMPv6 protocol identification
- Add IP_PROTO_ICMPV6 (58) constant to common.h
- Include ipv6_parse.h in packet_parser.c for protocol handling
- Modify parse_packet() function to handle ETH_TYPE_IPV6 (0x86DD) packets
- Support IPv6 TCP, UDP, and ICMPv6 protocol parsing
- Add ipv6_parse.c and ipv6_parse.h to CMakeLists.txt source and header lists
- Update banner information in main.c to display IPv6 support

## 2026-04-13

Added log file logging functionality

## 2026-04-11

Added ICMP protocol support to packet parser

- Add icmp_handler.c and icmp_handler.h to CMakeLists.txt source files
- Include ICMP header in packet_parser.c for protocol handling
- Change packet pointer type from const u_char to const unsigned char
- Implement ICMP protocol parsing logic in parse_packet function
- Add ICMP header parsing and printing functionality with error handling

## 2026-04-10

Added new fields to IPv4Header struct:

- flags - raw flags byte
- reserved - Reserved bit (bit 0)
- df - Don't Fragment flag (bit 1)
- mf - More Fragments flag (bit 2)
- fragment_offset - Fragment offset value (bits 3-15)