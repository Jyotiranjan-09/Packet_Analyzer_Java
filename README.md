# Packet Analyzer and Deep Packet Inspection (DPI) Engine - Java Port

This is a full Java port of the high-performance C++ Packet Analyzer project.

## Key Features
- **Packet Parser**: Handles Ethernet, VLAN, IPv4, TCP, UDP frames.
- **PCAP Reader**: Native Java binary stream parser.
- **Connection Tracker**: Thread-safe 5-tuple flow state management.
- **SNI Extractor**: Extracts TLS Client Hello SNI and HTTP Host headers.
- **DPI Engine**: Signature matching & protocol detection.
- **Fast Path Cache**: High-speed action resolution for established flows.
- **Load Balancer**: Multi-queue worker dispatching.

## Build and Run

```bash
mvn clean package
java -jar target/packet-analyzer-1.0.0.jar
```
