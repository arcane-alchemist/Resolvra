# Resolvra

A lightweight DNS server built from scratch in Java without third-party DNS libraries.

### Features
- UDP and TCP DNS support
- DNS packet parsing and encoding
- A, AAAA, CNAME, NS, MX, TXT and SOA records
- DNS compression
- NXDOMAIN and NODATA responses
- DNS class and opcode validation

### Run

```bash
javac -d out $(find src -name "*.java")
java -cp out dns.server.DnsServer
