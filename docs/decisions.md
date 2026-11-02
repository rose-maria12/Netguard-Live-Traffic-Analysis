# NetGuard Architecture & Design Decisions

## 1. Phase 1 Architecture Decisions

### 1.1 Timestamps & Timezones
- All timestamps in SQLite database (`packets`, `dns_events`, `captures`, `runs`) are stored as float UTC epoch seconds (`REAL`).
- Display conversion happens at the UI layer using `general.display_timezone` (default: `Asia/Kolkata`).

### 1.2 PCAP Ingestion & Streaming
- Uses Scapy `PcapReader` / `PcapNgReader` to stream packets one-by-one without loading entire captures into RAM.
- Format detection uses file magic bytes (`\xa1\xb2\xc3\xd4`, `\x0a\x0d\x0d\x0a`), not file extensions.
- Scope: Ethernet link-layer (`LinkType 1`), IPv4 network layer, TCP/UDP/ICMP transport protocols.
- Wireshark frame number compatibility: Maintains a 1-based sequential counter `frame_no` for every frame processed by Scapy (including skipped ones) so `packets.frame_no` matches Wireshark `frame.number`.

### 1.3 Database Storage
- SQLite using Python standard library `sqlite3`.
- `PRAGMA foreign_keys = ON` enforced on every database connection.
- Atomic single-transaction capture imports with batched inserts (5,000 rows per batch). If parsing fails mid-stream, transaction rolls back and capture status is marked `failed`.
