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