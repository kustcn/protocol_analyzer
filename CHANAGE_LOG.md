## 2026-04-10

Added new fields to IPv4Header struct:

- flags - raw flags byte
- reserved - Reserved bit (bit 0)
- df - Don't Fragment flag (bit 1)
- mf - More Fragments flag (bit 2)
- fragment_offset - Fragment offset value (bits 3-15)