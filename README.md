# HFL PCAP Analyzer v2.1

**[HACKFORLAB](https://hackforlab.com/) — Threat Intelligence Labs**

Enterprise-grade Network Behavior Anomaly Detection (NBAD/NABD) platform for deep PCAP analysis, passive threat hunting, and incident response support.

Pure Python — **zero external dependencies** for all core packet analysis. A single `.py` file delivers a complete threat hunting workstation.

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Installation & Requirements](#installation--requirements)
4. [Usage](#usage)
5. [Supported Input Formats](#supported-input-formats)
6. [Detection Engine](#detection-engine)
   - [Reconnaissance](#reconnaissance-nbad-01--09-nabd-31--35)
   - [C2 & Beaconing](#c2--beaconing-nbad-11--19-nabd-44-45-54)
   - [Malware Port Intelligence](#malware-port-intelligence-nbad-21)
   - [Data Exfiltration](#data-exfiltration-nbad-101--108-nabd-50-52-53)
   - [Denial of Service](#denial-of-service-nbad-109--113)
   - [Lateral Movement](#lateral-movement-nbad-117--124-nabd-46-48-49)
   - [Exploitation](#exploitation-nbad-125--129-170--173-nabd-38--42)
   - [Credential Attacks](#credential-attacks-nbad-135--139-191--194-nabd-34-36)
   - [Layer 2 Attacks](#layer-2-attacks-nbad-131--133-177--179)
   - [Cleartext Protocols](#cleartext-protocol-detection-nbad-141--146)
   - [Protocol Anomalies](#protocol-anomalies-nbad-147--152)
   - [Ransomware](#ransomware-nbad-155--156)
   - [Threat Actors & APT](#threat-actors--apt-nbad-159--160)
   - [RAT Families](#rat-family-detection)
   - [Malware Behavioral](#malware-behavioral-nbad-195--199)
   - [Advanced NABD Detections](#advanced-nabd-detections-nabd-38--55)
7. [Threat Scoring](#threat-scoring)
8. [Report Output](#report-output)
9. [MITRE ATT&CK Coverage](#mitre-attck-coverage)
10. [Architecture](#architecture)
11. [HFL Threat Intelligence Database](#hfl-threat-intelligence-database)
12. [GUI Mode](#gui-mode)
13. [JSON / SIEM Integration](#json--siem-integration)
14. [Troubleshooting](#troubleshooting)
15. [Security Notice](#security-notice)
16. [License](#license)

---

## Overview

**HFL PCAP Analyzer** is a passive threat hunting and incident response tool built by [HACKFORLAB](https://hackforlab.com/) Threat Intelligence Labs. It reads raw PCAP/PCAPNG captures and runs them through a **104-method NBAD/NABD detection engine** that simultaneously:

- Reconstructs all TCP/UDP/ICMP/DNS/HTTP/TLS **flows** from raw bytes
- Correlates every observed port against the **HFL Threat Intel Database** (566 malicious ports, 568 named malware families across 11 adversary categories)
- Executes **104 behavioral detection methods** covering 60+ attack classes
- Maps every finding to the **MITRE ATT&CK Enterprise Framework** with full technique and sub-technique details
- Generates a comprehensive **light-theme HTML report** with 6 interactive visualizations, tabular anomaly display, MITRE coverage breakdown, IR playbook, and hunting logic reference

The tool is designed for:
- **Security Operations Center (SOC)** analysts performing alert triage
- **Incident Responders (IR)** analyzing captured evidence
- **Threat Hunters** conducting proactive detection campaigns
- **Red Team / Blue Team** exercises validating detection coverage
- **DFIR** professionals needing offline PCAP analysis without network dependencies

---

## Key Features

| Feature | Detail |
|---------|--------|
| **Pure Python** | Zero external dependencies for core analysis (no scapy, dpkt, pyshark) |
| **Native PCAP parser** | Reads PCAP, PCAPNG, gzip-compressed captures from raw bytes |
| **104 detection methods** | 82 NBAD + 22 advanced NABD methods from real-world threat research |
| **566-port threat intel** | HFL PORT-Analysis Feed covering 568 named adversary families |
| **MITRE ATT&CK mapped** | Every detection linked to technique + sub-technique with clickable links |
| **Light professional theme** | High-contrast, print-friendly HTML reports suitable for management |
| **6 interactive charts** | Severity pie, category bar, MITRE tactic polar, protocol doughnut, timeline scatter, top-talker bubble |
| **HACKFORLAB brand links** | All HACKFORLAB references hyperlinked to [hackforlab.com](https://hackforlab.com/) |
| **Batch/glob analysis** | Analyze entire directories or wildcard-matched file sets |
| **GUI mode** | Tkinter drag-and-drop interface for non-CLI users |
| **JSON export** | SIEM-ready structured JSON output to stdout |
| **Auto REPORT/ folder** | Reports auto-saved with timestamp, no path setup required |

---

## Installation & Requirements

### Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Python | 3.8+ | All standard library modules only |
| Memory | 512 MB | For large (>1 GB) PCAP files, 2+ GB recommended |
| Disk | 50 MB free | For reports; source file is ~310 KB |
| OS | Any | Windows, macOS, Linux, WSL |

### No Installation Required

```bash
# Verify Python version (3.8+ required)
python3 --version

# Check tkinter availability (optional, for GUI mode only)
python3 -c "import tkinter; print('GUI: OK')"

# Verify the script runs
python3 HFL_PCAP_Analyzer.py --help
```

### Optional Enhancement

```bash
# gzip support is built-in (part of Python standard library)
# No pip installs required for any feature
# GUI mode uses tkinter which is pre-installed with most Python distributions

# On minimal Linux systems, if GUI is needed:
sudo apt-get install python3-tk   # Debian/Ubuntu
sudo yum install python3-tkinter  # CentOS/RHEL
```

---

## Usage

```bash
# ─── Interactive GUI (drag-and-drop) ───────────────────────────────────────
python3 HFL_PCAP_Analyzer.py

# ─── Single PCAP file ──────────────────────────────────────────────────────
python3 HFL_PCAP_Analyzer.py capture.pcap
python3 HFL_PCAP_Analyzer.py /absolute/path/to/capture.pcap
python3 HFL_PCAP_Analyzer.py C:\Users\Analyst\captures\traffic.pcap   # Windows

# ─── Entire directory (recursive, all .pcap/.pcapng/.cap) ─────────────────
python3 HFL_PCAP_Analyzer.py /path/to/pcap-folder/
python3 HFL_PCAP_Analyzer.py D:\Threat\PCAP\All-captures\

# ─── Glob / wildcard batch analysis ───────────────────────────────────────
python3 HFL_PCAP_Analyzer.py *.pcap
python3 HFL_PCAP_Analyzer.py "D:\captures\*.pcap"          # Windows (quote glob)
python3 HFL_PCAP_Analyzer.py /data/captures/*.pcapng
python3 HFL_PCAP_Analyzer.py /evidence/*traffic*.pcap

# ─── Custom report path ────────────────────────────────────────────────────
python3 HFL_PCAP_Analyzer.py capture.pcap -r /reports/investigation.html
python3 HFL_PCAP_Analyzer.py capture.pcap -r C:\Reports\case123.html

# ─── JSON output to stdout (SIEM ingest) ──────────────────────────────────
python3 HFL_PCAP_Analyzer.py capture.pcap --json
python3 HFL_PCAP_Analyzer.py capture.pcap --json > analysis.json

# ─── Skip HTML report generation ──────────────────────────────────────────
python3 HFL_PCAP_Analyzer.py capture.pcap --no-report

# ─── Demo mode (generates synthetic PCAP + analyzes) ──────────────────────
python3 HFL_PCAP_Analyzer.py --demo
python3 HFL_PCAP_Analyzer.py --demo -r demo_report.html
```

### Command-Line Arguments

| Argument | Description |
|----------|-------------|
| `[targets]` | One or more PCAP files, directories, or glob patterns |
| `-r <path>` | Custom output path for HTML report |
| `--json` | Output analysis as JSON to stdout |
| `--no-report` | Suppress HTML report generation |
| `--demo` | Generate and analyze a synthetic demonstration PCAP |
| `--help` / `-h` | Show help message |

### Report Output Location

By default, every analysis creates a report at:
```
<script_directory>/REPORT/HFL_YYYYMMDD_HHMMSS_<pcap_filename>.html
```

The `REPORT/` folder is created automatically beside `HFL_PCAP_Analyzer.py`. Use `-r` to override the path.

---

## Supported Input Formats

| Format | Extension | Notes |
|--------|-----------|-------|
| Standard PCAP (LE) | `.pcap` | libpcap little-endian (magic: `0xa1b2c3d4`) |
| Standard PCAP (BE) | `.pcap` | libpcap big-endian (magic: `0xd4c3b2a1`) |
| PCAP nanosecond (LE) | `.pcap` | Nanosecond timestamps (magic: `0xa1b23c4d`) |
| PCAP nanosecond (BE) | `.pcap` | Nanosecond timestamps (magic: `0x4d3cb2a1`) |
| AirPcap / Modified | `.pcap` | AirPcap variant (magic: `0xa1b2cd34`) |
| PCAPNG | `.pcapng` | Wireshark next-generation format |
| Compressed PCAP | `.pcap.gz` | gzip-compressed libpcap |
| Compressed PCAPNG | `.pcapng.gz` | gzip-compressed PCAPNG |
| Raw CAP | `.cap` | WinPcap/NetMon compatible |

---

## Detection Engine

The detection engine executes **104 independent methods** across 15 attack categories. Each method fires anomaly records with severity level, source/destination IPs and ports, MITRE ATT&CK technique ID, and a human-readable description.

### Reconnaissance (NBAD-01 — 09, NABD-31 — 35)

| ID | Detection | MITRE | Sub-Technique |
|----|-----------|-------|---------------|
| NBAD-01 | TCP/UDP Port Scan (>20 unique dst ports) | T1046 | Network Service Discovery |
| NBAD-02 | Stealth Scans: FIN, NULL, XMAS | T1046 | Network Service Discovery |
| NBAD-03 | OS Fingerprinting via TTL anomalies | T1592 | Gather Victim Host Information |
| NBAD-04 | ICMP/TCP Network Sweep (>15 hosts) | T1046 | Network Service Discovery |
| NBAD-05 | Service Version Probing (banner grabbing) | T1046 | Network Service Discovery |
| NBAD-06 | SNMP Enumeration (UDP/161-162) | T1046 | Network Service Discovery |
| NBAD-07 | SMB/NetBIOS Enumeration | T1135 | Network Share Discovery |
| NBAD-08 | LDAP Enumeration / Directory Queries | T1087 | Account Discovery |
| NBAD-09 | DNS Zone Transfer (AXFR/IXFR requests) | T1590 | Gather Victim Network Information |
| NABD-31 | TCP Connect Scan (full 3-way handshake) | T1046 | Network Service Discovery |
| NABD-32 | TCP ACK Scan (firewall rule mapping) | T1046 | Network Service Discovery |
| NABD-33 | Slow Service Enumeration (APT-style) | T1046 | Network Service Discovery |
| NABD-35 | Web Directory Brute Force (forced browsing, >30 unique URIs) | T1083 | File and Directory Discovery |

### C2 & Beaconing (NBAD-11 — 19, NABD-44, 45, 54)

| ID | Detection | MITRE | Description |
|----|-----------|-------|-------------|
| NBAD-11 | Periodic Beaconing (CV < 0.20) | T1071 | Regular interval connections to external host |
| NBAD-12 | IRC C2 (ports 6667/6697) | T1071.003 | IRC protocol used as C2 channel |
| NBAD-13 | HTTP/HTTPS C2 (suspicious user agents) | T1071.001 | Web protocol C2 with known RAT user-agent strings |
| NBAD-14 | DNS C2 (high-entropy subdomains, avg label >30 chars) | T1071.004 | DNS used as covert C2 channel |
| NBAD-15 | ICMP C2 (oversized ICMP packets >100 bytes) | T1095 | ICMP used for covert command tunneling |
| NBAD-16 | DGA Activity (Shannon entropy >3.5, vowel ratio <20%) | T1568.002 | Domain Generation Algorithm detected |
| NBAD-17 | Fast-Flux DNS (domain resolves to >4 distinct IPs) | T1568.001 | Fast-flux DNS infrastructure for C2 evasion |
| NBAD-18 | Tor Network Usage (ports 9001/9050/9150) | T1090.003 | Anonymized C2 through onion routing |
| NBAD-19 | C2 Framework Ports (Cobalt Strike, Sliver, Metasploit) | T1219 | Known C2 framework port indicators |
| NBAD-187 | Domain Fronting (SNI ≠ HTTP Host header) | T1090.004 | CDN-based C2 domain fronting |
| NBAD-188 | Long-Lived Sessions (>1 hour to external host) | T1071 | Persistent RAT/implant connection |
| NBAD-189 | Port Knocking Pattern (sequential single-SYN probes) | T1571 | Covert authentication via port knocking |
| NABD-44 | HTTP Header Covert Channel (high-entropy User-Agent) | T1071.001 | Data exfil via crafted HTTP headers |
| NABD-45 | DNS-over-HTTPS/TLS Abuse for C2 | T1071.004 | DoH/DoT used to tunnel C2 traffic |
| NABD-54 | Precise Beacon IAT Analysis (CV < 0.15) | T1071 | Statistical beacon timing analysis |

### Malware Port Intelligence (NBAD-21)

The HFL Threat Intel Database is checked against every observed port. **566 unique ports** map to **568 named malware families** across 11 adversary categories.

| Severity | Categories |
|----------|-----------|
| **CRITICAL** | Threat Actor, Rootkit, Ransomware, Backdoor |
| **HIGH** | Botnet, Trojan, Spyware, Worm, Malware, Phishing Campaign |
| **MEDIUM** | P2P / File Sharing |

**Coverage breakdown:**

| Category | Ports | Example Malware Families |
|----------|-------|--------------------------|
| Malware | 466 | NetBus, SubSeven, Back Orifice, Gh0st RAT, Poison Ivy |
| Worm | 55 | Conficker, Blaster, Mydoom, Sasser, Bagle, Zotob |
| Spyware | 50 | NjRAT, Remcos, QuasarRAT, AsyncRAT, DarkComet |
| Trojan | 33 | TrickBot, Emotet, Dridex, Hesperbot, Zeus, Citadel |
| Threat Actor | 19 | APT28, APT36, UNC5174, UAC-0226, UTG-Q-015 |
| Ransomware | 14 | DragonForce, Datacarry, Crypto24, LockBit C2 |
| Rootkit | 10 | T0rn, ZeroAccess, TDSS, Rustock, FU Rootkit |
| Botnet | 9 | Pushdo, SubSeven C2, Back Orifice, Kaiten C2 |
| Backdoor | 2 | Anubis Backdoor, Metasploit listener |
| P2P | 3 | Kazaa, BitTorrent, Gnutella |
| Phishing | 1 | W3LL Phishing Kit (Signal port abuse) |

### Data Exfiltration (NBAD-101 — 108, NABD-50, 52, 53)

| ID | Detection | MITRE | Threshold / Method |
|----|-----------|-------|-------------------|
| NBAD-101 | Large Outbound Transfer | T1041 | >10 MB to external IP |
| NBAD-102 | High-Rate Exfiltration | T1041 | >5 MB/s sustained |
| NBAD-103 | DNS Tunneling | T1048.003 | avg subdomain label >30 chars |
| NBAD-104 | ICMP Tunneling | T1095 | ICMP payload >100 bytes |
| NBAD-105 | HTTP POST Exfiltration | T1048.002 | Large POST to external host |
| NBAD-106 | Slow-Drip Exfiltration | T1048 | Low-rate sustained outbound |
| NBAD-182 | SMTP Exfiltration | T1048.002 | >1 MB over mail protocol ports |
| NBAD-183 | FTP Exfiltration | T1048.003 | FTP data transfer to external |
| NBAD-184 | Cloud/Paste-Site Exfil | T1567 | pastebin, mega, transfer.sh, anonfile |
| NABD-50 | Chunked HTTP Exfiltration | T1048 | Many small POSTs to same external host |
| NABD-52 | Protocol Masquerading | T1571 | HTTP on non-80, DNS on non-53 |
| NABD-53 | Internal Lateral Exfiltration | T1074 | Large internal-to-internal transfers (staging) |
| NABD-55 | High-Entropy Payload Detection | T1027 | Payload entropy >7.2 (packed/encrypted) |

### Denial of Service (NBAD-109 — 113)

| ID | Detection | MITRE | Threshold |
|----|-----------|-------|-----------|
| NBAD-109 | SYN Flood | T1498.001 | >10 SYN/s from single source |
| NBAD-110 | UDP Flood | T1498 | >500 UDP packets from single source |
| NBAD-111 | ICMP Flood / Smurf | T1498 | >200 ICMP packets from single source |
| NBAD-112 | HTTP Flood | T1499 | >100 requests to same host |
| NBAD-113 | Amplification Attacks | T1498.002 | DNS/NTP/SSDP request-to-response size ratio |

### Lateral Movement (NBAD-117 — 124, NABD-46, 48, 49)

| ID | Detection | MITRE | Trigger |
|----|-----------|-------|---------|
| NBAD-117 | SMB Lateral Movement | T1021.002 | SMB to >3 distinct internal hosts |
| NBAD-118 | RDP Lateral Movement | T1021.001 | RDP to >2 distinct internal hosts |
| NBAD-119 | SSH Lateral Movement | T1021.004 | SSH to >3 distinct internal hosts |
| NBAD-120 | WMI/DCOM Lateral Movement | T1021.003 | RPC + SMB correlation, WMI query patterns |
| NBAD-121 | PsExec-Style Execution | T1570 | SMB + high ephemeral port correlation |
| NBAD-122 | Pass-the-Hash | T1550.002 | Rapid SMB auth spread across >3 hosts |
| NBAD-123 | Kerberoasting | T1558.003 | Multiple TGS ticket requests (>5 in session) |
| NBAD-124 | WinRM Abuse | T1021.006 | Connections to 5985/5986/47001 |
| NABD-46 | SMB Tree Connect / IPC$ Abuse | T1021.002 | IPC$ traversal across multiple hosts |
| NABD-48 | Remote Service / Task Creation | T1543.003 | RPC/135 + ephemeral SMB correlation |
| NABD-49 | Internal East-West Network Scan | T1046 | Internal host scanning >25 ports |

### Exploitation (NBAD-125 — 129, 170 — 173, NABD-38 — 42)

| ID | Detection | MITRE | Payload/Pattern |
|----|-----------|-------|----------------|
| NBAD-125 | SQL Injection | T1190 | UNION SELECT, OR 1=1, xp_cmdshell, SLEEP() |
| NBAD-126 | Command Injection | T1190 | `;id`, `\|whoami`, `$(cmd)`, backtick execution |
| NBAD-127 | Directory Traversal | T1083 | `../../etc/passwd`, `..\..\\windows\\system32` |
| NBAD-128 | Shellshock (CVE-2014-6271) | T1190 | `(){:;};` in HTTP headers |
| NBAD-129 | Log4Shell (CVE-2021-44228) | T1190 | `${jndi:ldap://...}` in any header/body |
| NBAD-170 | ProxyShell / Exchange RCE | T1190 | Exchange AutoDiscover + SSRF patterns |
| NBAD-171 | Spring4Shell | T1190 | `class.module.classloader` parameter |
| NBAD-172 | XXE / SSRF Injection | T1190 | `<!DOCTYPE`, `SYSTEM "file://`, `169.254.169.254` |
| NBAD-173 | Java/.NET Deserialization | T1190 | `aced0005`, `rO0AB`, `AAEAAAD` byte magic |
| NABD-38 | Buffer Overflow Payloads | T1190 | NOP sled (0x90 runs), cyclic filler patterns |
| NABD-39 | Exploit Kit Traffic | T1189 | EK URI patterns (`/gate.php`, `/panel/`), old IE |
| NABD-40 | Malicious Payload Download | T1105 | .exe/.dll/.ps1 downloads, PE/ELF magic bytes |
| NABD-41 | HTTP Request Smuggling | T1190 | Conflicting Content-Length + Transfer-Encoding |
| NABD-42 | Fileless / LOTL Exploitation | T1059.001 | PowerShell `-enc`, `IEX`, `Invoke-`, `DownloadString` |

### Credential Attacks (NBAD-135 — 139, 191 — 194, NABD-34, 36)

| ID | Detection | MITRE | Service / Method |
|----|-----------|-------|----------------|
| NBAD-135 | SSH Brute Force | T1110.001 | >10 auth failures to port 22 |
| NBAD-136 | HTTP Auth Brute Force | T1110.001 | >10 auth failures (401 responses) |
| NBAD-137 | RDP Brute Force | T1110.001 | >5 connection attempts to port 3389 |
| NBAD-138 | FTP Brute Force | T1110.001 | >10 auth failures to port 21 |
| NBAD-139 | Default Credential Usage | T1078.001 | Known default username patterns detected |
| NBAD-191 | AS-REP Roasting | T1558.004 | Kerberos pre-auth disabled, hash exposed |
| NBAD-192 | LDAP Brute Force | T1110.001 | >15 LDAP bind failures (port 389/636) |
| NBAD-193 | SMB Authentication Brute Force | T1110.001 | >8 SMB NTLM failures from one source |
| NBAD-194 | NTLM Relay Attack | T1557.001 | NTLM auth redirected to attacker host |
| NABD-34 | Low-and-Slow Password Spraying | T1110.003 | Time-spread auth attempts across multiple hosts |
| NABD-36 | NTLM Downgrade (NTLMv1) | T1557.001 | NTLMv1 negotiation via small SMB auth packets |

### Layer 2 Attacks (NBAD-131 — 133, 177 — 179)

| ID | Detection | MITRE | Trigger |
|----|-----------|-------|---------|
| NBAD-131 | ARP Spoofing / Cache Poisoning | T1557.002 | Same IP multiple different MACs |
| NBAD-132 | ARP Network Scan | T1046 | >20 ARP requests from single MAC |
| NBAD-133 | MAC Flooding (CAM Overflow) | T1557 | >100 distinct source MACs observed |
| NBAD-177 | DHCP Starvation / Rogue DHCP | T1557 | DHCP discover storm from many MACs |
| NBAD-178 | STP Manipulation | T1557 | Unexpected STP topology change BPDUs |
| NBAD-179 | VLAN Hopping (Double Tagging) | T1557 | Double 802.1Q VLAN tag detected |

### Cleartext Protocol Detection (NBAD-141 — 146)

| ID | Detection | MITRE | Protocol |
|----|-----------|-------|----------|
| NBAD-141 | Cleartext FTP Credentials | T1040 | FTP USER/PASS commands in plaintext |
| NBAD-142 | Telnet Usage | T1040 | Port 23 session with credential-like payloads |
| NBAD-143 | HTTP Basic Auth in Cleartext | T1040 | Authorization: Basic header over HTTP |
| NBAD-144 | POP3/IMAP Credentials | T1040 | Mail client auth over plaintext |
| NBAD-145 | SNMP v1/v2c Community Strings | T1040 | SNMP community string visible in UDP |
| NBAD-146 | LDAP Cleartext Bind | T1040 | LDAP simple bind on port 389 (non-TLS) |

### Protocol Anomalies (NBAD-147 — 152)

| ID | Detection | MITRE | Description |
|----|-----------|-------|-------------|
| NBAD-147 | Deprecated TLS/SSL | T1600 | SSLv2, SSLv3, TLS 1.0, TLS 1.1 detected |
| NBAD-148 | Invalid TCP Flag Combinations | T1095 | SYN+FIN, RST+FIN, or all flags set |
| NBAD-149 | Oversized DNS Queries | T1048 | DNS query >100 bytes (tunneling indicator) |
| NBAD-150 | GRE Tunneling | T1572 | Generic Routing Encapsulation covert channel |
| NBAD-151 | SOCKS Proxy Detection | T1090 | SOCKS4/SOCKS5 handshake patterns |
| NBAD-152 | HTTP CONNECT Tunneling | T1572 | HTTP CONNECT method used for proxy tunneling |
| NABD-43 | TLS Certificate Abuse | T1573 | TLS on non-standard high ports (C2 evasion) |

### Ransomware (NBAD-155 — 156)

| ID | Detection | MITRE | Description |
|----|-----------|-------|-------------|
| NBAD-155 | Ransomware C2 Ports | T1486 | DragonForce, Datacarry, Crypto24 signature ports |
| NBAD-156 | SMB Encryption Sweep | T1486 | Rapid write operations to >5 SMB shares |

### Threat Actors & APT (NBAD-159 — 160)

| ID | Detection | MITRE | Actors |
|----|-----------|-------|--------|
| NBAD-159 | APT/Nation-State Ports | T1071 | APT28, APT36, UNC5174, UAC-0226, UTG-Q-015 |
| NBAD-160 | Rootkit Port Signatures | T1014 | T0rn, ZeroAccess, TDSS, Sub7, Rustock |

### RAT Family Detection

Multi-port signature matching: fires when **2 or more** known ports for the same RAT family appear in the capture. MITRE: **T1219** (Remote Access Software).

| RAT Family | Signature Ports | Notes |
|-----------|----------------|-------|
| NjRAT | 1177, 1604, 2404, 3393, 5552, 6666, 8888, 27375, 48905 | Bladabindi; MENA-region linked |
| AsyncRAT | 2404, 3393, 6666, 8888, 27375, 48905 | Open-source .NET RAT |
| QuasarRAT | 1604, 2404, 3393, 4782, 4783, 6666, 8888, 27375, 48905 | Open-source .NET RAT |
| RemcosRAT | 2404, 3000, 3100, 3393, 3500, 3980, 5552, 5650, 6666, 7000, 8888, 27015, 27375, 48905 | Commercial surveillance RAT |
| XWorm | 4226, 6000, 7000, 51598, 53795 | Commodity C2 RAT |
| DarkComet | 1042, 1604, 8080, 8181, 9001 | Legacy surveillance RAT |
| DarkTrack | 1604, 1991, 5552 | .NET surveillance RAT |
| Gh0st RAT | 1234, 7070 | China-linked APT tool |
| NanoCore | 1234, 1337, 8000 | Plugin-based .NET RAT |
| Netwire | 4433, 5060, 8080, 9000, 9001 | Cross-platform commercial RAT |
| WarzoneRAT | 1034, 1035, 1036, 1037 | AVENUE RAT commodity malware |
| PoisonIvy | 3460, 3461, 3462 | Classic APT RAT tool |
| Sliver C2 | 1337, 5353, 8888, 51820 | Open-source C2 framework |
| Empire C2 | 2222 | PowerShell post-exploitation framework |
| Cobalt Strike | 80, 443, 2222, 4444, 8080, 8443, 50050 | Commercial adversary simulation |
| Metasploit | 1234, 4444, 4445, 4446, 8443 | Open-source exploit framework |
| PupyRAT | 2345, 4433, 9001 | Cross-platform open-source RAT |
| SparkRAT | 1256 | Go-based cross-platform RAT |

### Malware Behavioral (NBAD-195 — 199)

| ID | Detection | MITRE | Description |
|----|-----------|-------|-------------|
| NBAD-195 | Worm Propagation | T1210 | Single host probes >20 hosts on same service port |
| NBAD-196 | P2P Activity | T1071 | BitTorrent, Kazaa, Gnutella, eMule port signatures |
| NBAD-197 | Phishing Infrastructure | T1566 | W3LL Kit, Signal port abuse, known phishing ports |
| NBAD-198 | Spyware Surveillance Ports | T1219 | NjRAT/Remcos/QuasarRAT port hits to external |
| NBAD-199 | Multi-Stage Attack Correlation | T1059 | 3+ kill-chain stages from same source IP |

### Advanced NABD Detections (NABD-38 — 55)

*(See individual sections above for full details)*

| NABD ID | Attack | MITRE |
|---------|--------|-------|
| NABD-38 | Buffer Overflow (NOP sled, cyclic filler) | T1190 |
| NABD-39 | Exploit Kit Traffic (EK URI patterns) | T1189 |
| NABD-40 | Malicious Payload Download (.exe, .dll, PE header) | T1105 |
| NABD-41 | HTTP Request Smuggling / Desync | T1190 |
| NABD-42 | Fileless / PowerShell LOTL | T1059.001 |
| NABD-43 | TLS Certificate Abuse on non-standard ports | T1573 |
| NABD-44 | HTTP Header Covert Channel (User-Agent entropy) | T1071.001 |
| NABD-45 | DNS-over-HTTPS/TLS Abuse | T1071.004 |
| NABD-46 | SMB Tree / IPC$ Abuse | T1021.002 |
| NABD-48 | Remote Service / Scheduled Task Creation | T1543.003 |
| NABD-49 | Internal East-West Network Scan | T1046 |
| NABD-50 | Chunked HTTP Exfiltration | T1048 |
| NABD-52 | Protocol Masquerading | T1571 |
| NABD-53 | Internal-to-Internal Lateral Exfiltration | T1074 |
| NABD-54 | Beacon Inter-Arrival Time Analysis (CV < 0.15) | T1071 |
| NABD-55 | High-Entropy Payload Detection (entropy > 7.2) | T1027 |

---

## Threat Scoring

The threat score (0–100) is computed as a capped sum of anomaly severity weights:

| Anomaly Severity | Score Weight |
|-----------------|-------------|
| CRITICAL | +25 per detection |
| HIGH | +15 per detection |
| MEDIUM | +8 per detection |
| LOW | +3 per detection |
| INFO | +0 (informational only) |

| Final Score | Risk Level | Color |
|------------|-----------|-------|
| 0 | CLEAN | Green |
| 1 – 14 | LOW | Yellow |
| 15 – 29 | MEDIUM | Orange |
| 30 – 49 | HIGH | Red |
| 50 – 100 | CRITICAL | Dark Red |

---

## Report Output

### HTML Report (Default)

Auto-saved to `REPORT/HFL_YYYYMMDD_HHMMSS_<pcap_name>.html`.

The report is a **single self-contained HTML file** with inline CSS and Chart.js charts loaded from CDN. It can be opened in any browser, printed, or emailed without dependencies.

#### Report Sections

| Section | Description |
|---------|-------------|
| **Classification Banner** | "For Official Use Only" header with [HACKFORLAB](https://hackforlab.com/) link |
| **Report Header** | File metadata, SHA-256 hash, report ID, generation timestamp |
| **Threat Score Gauge** | Animated circular gauge with score / 100 and risk level badge |
| **Summary Cards** | Packets, data volume, duration, unique IPs, external IPs, flows, DNS queries, HTTP requests, MITRE techniques |
| **Severity Distribution Pie** | Doughnut chart: Critical / High / Medium / Low / Info |
| **Attack Category Bar** | Horizontal bar chart of detection categories sorted by count |
| **MITRE Tactic Polar** | Polar area chart grouping detections by ATT&CK tactic |
| **Protocol Doughnut** | Protocol distribution (TCP / UDP / ICMP / ARP / other) |
| **Detection Timeline** | Scatter chart plotting severity score vs. detection sequence |
| **Top Talker Bubbles** | Bubble chart: top 10 source IPs, bubble size = packet volume |
| **Severity Overview** | Count boxes for each severity level |
| **Anomaly Table** | Filterable table: Severity · Source IP · Src Port · Dest IP · Dst Port · Flows · Attack Name · MITRE Link · Tactic · Category · Description |
| **MITRE ATT&CK Full Coverage** | Per-tactic grouping of all detected techniques with clickable attack.mitre.org links, tactic labels, descriptions, and hit-count bars |
| **Top Network Flows** | Tabular: Source IP · Src Port · Dest IP · Dst Port · Protocol · Packets · Data · Duration · Direction |
| **Protocol Distribution** | Table with packet counts and visual percentage bars |
| **DNS Analysis** | Top domains by query count with frequency bars |
| **HTTP Analysis** | Top 20 requests: method, host, URI, source IP, user-agent |
| **TLS Analysis** | Version breakdown, deprecated protocol flags, SNI list |
| **IOC Table** | All extracted indicators: IPs, domains, URLs, SNIs, malware hits |
| **Top Talkers** | Source and destination IP tables with Internal/External classification |
| **NABD Hunting Logic** | 6 color-coded IF/AND/THEN logic blocks with MITRE links |
| **IR Response Playbook** | 6-phase IR model: Detection → Scoping → Containment → Eradication → Recovery → Lessons Learned |

### JSON Output (`--json`)

Structured JSON to stdout, suitable for SIEM ingestion (Splunk, Elastic, QRadar, etc.):

```json
{
  "file_info": {
    "filename": "capture.pcap",
    "sha256": "abc123...",
    "size_bytes": 1048576,
    "size_human": "1.0 MB"
  },
  "summary": {
    "total_packets": 15432,
    "total_bytes": 1048576,
    "total_bytes_human": "1.0 MB",
    "duration_seconds": 3600.0,
    "duration_human": "1:00:00",
    "unique_ips": 24,
    "external_ips": 8,
    "total_flows": 312
  },
  "risk_level": "HIGH",
  "threat_score": 75,
  "anomalies": [
    {
      "severity": "critical",
      "category": "C2_BEACONING",
      "description": "C2 Beaconing detected: 192.168.1.10 → 185.234.x.x (interval 30.02s, CV=0.04)",
      "mitre": "T1071",
      "source": "192.168.1.10",
      "destination": "185.234.x.x"
    }
  ],
  "iocs": [
    { "type": "external_ip", "value": "185.234.x.x" },
    { "type": "domain", "value": "evil.c2domain.com" }
  ],
  "protocols": { "TCP": 12000, "UDP": 3200, "ICMP": 232 },
  "top_talkers_src": { "192.168.1.10": 5420 }
}
```

---

## MITRE ATT&CK Coverage

The tool detects techniques across **11 ATT&CK tactics**. All technique IDs in the report are **hyperlinked to the official MITRE ATT&CK knowledge base** at attack.mitre.org.

### Full Technique Coverage

| Technique ID | Name | Tactic |
|-------------|------|--------|
| T1014 | Rootkit | Defense Evasion |
| T1018 | Remote System Discovery | Discovery |
| T1021 | Remote Services | Lateral Movement |
| T1021.001 | Remote Services: RDP | Lateral Movement |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement |
| T1021.003 | Remote Services: DCOM | Lateral Movement |
| T1021.004 | Remote Services: SSH | Lateral Movement |
| T1021.006 | Remote Services: WinRM | Lateral Movement |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1040 | Network Sniffing | Credential Access |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1046 | Network Service Discovery | Reconnaissance |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1048.001 | Exfil: Symmetric Encrypted Non-C2 Protocol | Exfiltration |
| T1048.002 | Exfil: SMTP / Asymmetric Encrypted | Exfiltration |
| T1048.003 | Exfil: FTP / DNS Unencrypted | Exfiltration |
| T1059 | Command and Scripting Interpreter | Execution |
| T1059.001 | Scripting: PowerShell | Execution |
| T1071 | Application Layer Protocol | Command and Control |
| T1071.001 | App Layer Protocol: Web (HTTP/HTTPS) | Command and Control |
| T1071.003 | App Layer Protocol: Mail (IRC) | Command and Control |
| T1071.004 | App Layer Protocol: DNS | Command and Control |
| T1074 | Data Staged | Collection |
| T1078 | Valid Accounts | Defense Evasion |
| T1078.001 | Valid Accounts: Default Accounts | Defense Evasion |
| T1083 | File and Directory Discovery | Discovery |
| T1087 | Account Discovery | Discovery |
| T1090 | Proxy | Command and Control |
| T1090.003 | Proxy: Multi-hop / Tor | Command and Control |
| T1090.004 | Proxy: Domain Fronting | Command and Control |
| T1095 | Non-Application Layer Protocol | Command and Control |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1110 | Brute Force | Credential Access |
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1110.003 | Brute Force: Password Spraying | Credential Access |
| T1135 | Network Share Discovery | Discovery |
| T1189 | Drive-by Compromise | Initial Access |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1210 | Exploitation of Remote Services | Lateral Movement |
| T1219 | Remote Access Software | Command and Control |
| T1486 | Data Encrypted for Impact | Impact |
| T1498 | Network Denial of Service | Impact |
| T1498.001 | Network DoS: Direct Network Flood | Impact |
| T1498.002 | Network DoS: Reflection Amplification | Impact |
| T1499 | Endpoint Denial of Service | Impact |
| T1543.003 | Create/Modify System Process: Windows Service | Persistence |
| T1550 | Use Alternate Authentication Material | Lateral Movement |
| T1550.002 | Use Alternate Auth: Pass the Hash | Lateral Movement |
| T1557 | Adversary-in-the-Middle | Credential Access |
| T1557.001 | AiTM: LLMNR/NBT-NS Poisoning & SMB Relay | Credential Access |
| T1557.002 | AiTM: ARP Cache Poisoning | Credential Access |
| T1558 | Steal or Forge Kerberos Tickets | Credential Access |
| T1558.003 | Kerberos: Kerberoasting | Credential Access |
| T1558.004 | Kerberos: AS-REP Roasting | Credential Access |
| T1566 | Phishing | Initial Access |
| T1567 | Exfiltration Over Web Service | Exfiltration |
| T1568 | Dynamic Resolution | Command and Control |
| T1568.001 | Dynamic Resolution: Fast Flux DNS | Command and Control |
| T1568.002 | Dynamic Resolution: DGA | Command and Control |
| T1570 | Lateral Tool Transfer | Lateral Movement |
| T1571 | Non-Standard Port | Command and Control |
| T1572 | Protocol Tunneling | Command and Control |
| T1573 | Encrypted Channel | Command and Control |
| T1590 | Gather Victim Network Information | Reconnaissance |
| T1592 | Gather Victim Host Information | Reconnaissance |
| T1600 | Weaken Encryption | Defense Evasion |

---

## Architecture

```
HFL_PCAP_Analyzer.py (single file, ~311 KB, ~5,830 lines)
│
├── CONSTANTS & DATABASES
│   ├── MALICIOUS_PORTS_DB      — 566 ports × 568 malware family names
│   ├── C2_FRAMEWORK_PORTS      — 45 C2 framework signature ports
│   ├── RANSOMWARE_PORTS        — 14 ransomware C2 signature ports
│   ├── THREAT_ACTOR_PORTS      — 19 APT/nation-state ports
│   ├── ROOTKIT_PORTS           — 10 rootkit signature ports
│   ├── BOTNET_PORTS            — 9 botnet C2 ports
│   └── RAT_FAMILIES            — 18 RAT families × multi-port signatures
│
├── PcapParser
│   ├── _open_file()            — PCAP/PCAPNG/gzip auto-detection (8 magic variants)
│   ├── _parse_pcap()           — libpcap record-level parser
│   ├── _parse_pcapng()         — PCAPNG block parser (IDB, EPB, SPB)
│   └── parse()                 — Returns list of raw packet dicts
│
├── ProtocolDissector
│   ├── dissect()               — Ethernet/IP/transport dispatcher
│   ├── _parse_ethernet()       — EtherType: IPv4, IPv6, ARP, VLAN (802.1Q)
│   ├── _parse_ipv4()           — IP header, TTL, fragmentation flags
│   ├── _parse_tcp()            — TCP flags, sequence tracking, payload
│   ├── _parse_udp()            — UDP header + payload
│   ├── _parse_icmp()           — ICMP type/code + payload size
│   ├── _parse_dns()            — DNS query/response, QTYPE, QNAME
│   ├── _parse_http()           — HTTP/1.x request/response, headers, URI
│   └── _parse_tls()            — TLS record header, version, SNI extension
│
├── TrafficAnalyzer (104 detection methods)
│   ├── Reconnaissance          — 11 methods (NBAD-01 to 09, NABD-31/32/33/35)
│   ├── C2 / Beaconing          — 15 methods (NBAD-11 to 19, 187-189, NABD-44/45/54)
│   ├── Malware Ports           — DB-driven port matching (NBAD-21)
│   ├── Exfiltration            — 13 methods (NBAD-101 to 108, NABD-50/52/53/55)
│   ├── DoS                     — 5 methods (NBAD-109 to 113)
│   ├── Lateral Movement        — 11 methods (NBAD-117 to 124, NABD-46/48/49)
│   ├── Exploitation            — 13 methods (NBAD-125 to 129/170-173, NABD-38 to 42)
│   ├── Credential Attacks      — 11 methods (NBAD-135 to 139/191-194, NABD-34/36)
│   ├── Layer 2                 — 6 methods (NBAD-131/132/133/177/178/179)
│   ├── Cleartext               — 6 methods (NBAD-141 to 146)
│   ├── Protocol Anomaly        — 7 methods (NBAD-147 to 152, NABD-43)
│   ├── Ransomware              — 2 methods (NBAD-155/156)
│   ├── Threat Actors           — 2 methods (NBAD-159/160)
│   ├── RAT Families            — Multi-port signature matching (18 families)
│   └── Malware Behavioral      — 5 methods (NBAD-195 to 199)
│
├── DemoGenerator
│   └── create()                — Generates synthetic PCAP for testing/demonstration
│
├── ReportGenerator (v4.0)
│   ├── MITRE_DB                — Full ATT&CK catalogue (60+ techniques + sub-techniques)
│   ├── _mitre_info()           — Lookup with graceful fallback to base technique
│   └── generate()              — Light-theme HTML report with:
│       ├── 6 Chart.js visualizations
│       ├── Full MITRE tactic/technique breakdown with clickable links
│       ├── Tabular anomaly display with severity filters
│       ├── Structured flow table (src/dst IP+port, protocol, direction)
│       ├── NABD hunting logic reference
│       └── 6-phase IR playbook
│
├── PacketCaptureAnalyzer
│   └── analyze_file()          — Orchestrates parse → dissect → analyze → report
│
└── main()
    ├── _resolve_targets()      — Any path: file / directory / glob / Windows path
    ├── _report_dir()           — Auto-creates REPORT/ beside script
    ├── _report_filename()      — HFL_YYYYMMDD_HHMMSS_<n>.html
    └── GUI launcher            — Tkinter drag-and-drop interface
```

---

## HFL Threat Intelligence Database

Source: **HFL PORT-Analysis Feed** — curated by [HACKFORLAB](https://hackforlab.com/) Threat Intelligence Labs.

- **566 unique malicious ports** mapped to **568 adversary names**
- **11 adversary categories**: Malware, Worm, Spyware, Trojan, Threat Actor, Ransomware, Rootkit, Botnet, Backdoor, P2P, Phishing Campaign
- **18 RAT family multi-port signatures** with 2-of-N matching logic

Top ports by malware family density:

| Port | Families | Top Malware |
|------|---------|-------------|
| 6667 | 23 | Various IRC Bots, SubSeven, Kaiten C2, PoisonIvy |
| 8080 | 22 | DarkComet, Netwire, TrickBot, Emotet, Zeus, Cobetstrike |
| 12345 | 21 | NetBus, Fizzer, Turkojan, Bandook, W32/Myputs |
| 31337 | 20 | Back Orifice, Spybot, NoBackO, Phase Zero |
| 4444 | 20 | Metasploit, Stuxnet, Zeus, Datacarry, Blaster |
| 1025 | 17 | Conficker, Optix Pro, Remote Explorer, Moonpie |
| 8888 | 16 | NjRAT, AsyncRAT, APT28, Sliver C2, Marap |
| 4433 | 16 | Netwire, Waledac, SpyEye, APT28 |
| 21 | 17 | Blade Runner, Cattivik FTP, Doly Trojan, DarkFTP |
| 5534 | 17 | Blade Runner, Doly Trojan, WinCrash, Priority |

---

## GUI Mode

Launch without arguments to open the interactive GUI:

```bash
python3 HFL_PCAP_Analyzer.py
```

GUI Features:
- **Drag-and-drop** PCAP files directly onto the window
- **Browse** button for file/folder selection
- **Real-time log** output showing packet processing progress
- **Progress bar** during analysis
- **Open Report** button to launch the HTML report in the default browser
- Requires `tkinter` (pre-installed with most Python distributions)

---

## JSON / SIEM Integration

Use `--json` flag to output analysis as structured JSON for ingestion into:

| Platform | Integration Method |
|----------|--------------------|
| **Splunk** | `python3 HFL_PCAP_Analyzer.py cap.pcap --json \| splunk add oneshot -` |
| **Elastic/Kibana** | Pipe JSON to `filebeat` or `logstash` pipeline |
| **QRadar** | Use as event source via Python log forward |
| **Microsoft Sentinel** | HTTP Data Collector API ingestion |
| **Custom SIEM** | Parse `anomalies[]` array with `severity`, `mitre`, `category` fields |

### Key JSON Fields for SIEM Mapping

| Field | Type | Description |
|-------|------|-------------|
| `risk_level` | string | CLEAN / LOW / MEDIUM / HIGH / CRITICAL |
| `threat_score` | integer | 0–100 composite threat score |
| `anomalies[].severity` | string | critical / high / medium / low / info |
| `anomalies[].mitre` | string | MITRE ATT&CK technique ID (e.g., T1071.001) |
| `anomalies[].category` | string | C2_BEACONING, PORT_SCAN, LATERAL_MOVEMENT, etc. |
| `anomalies[].source` | string | Source IP address |
| `anomalies[].destination` | string | Destination IP address |
| `iocs[].type` | string | external_ip, domain, url, tls_sni, malware_port |
| `iocs[].value` | string | IOC value |

---

## Troubleshooting

### Common Issues

**`Error: Unknown PCAP magic byte`**
The capture format is not recognized. Check the file is not corrupted. The tool supports 8 PCAP magic variants including AirPcap. If it's a truly exotic format (e.g., ERF/nfcapd), convert with `tcpdump -r input.pcap -w output.pcap` first.

**`tkinter not found` (GUI mode)**
Install tkinter for your OS:
```bash
sudo apt-get install python3-tk       # Debian/Ubuntu
sudo yum install python3-tkinter      # RHEL/CentOS
brew install python-tk                 # macOS
```
Or use CLI mode: `python3 HFL_PCAP_Analyzer.py capture.pcap`

**`MemoryError` on large PCAP files**
For files >500 MB, increase available RAM or split the capture:
```bash
# Split with tcpdump (process in 100 MB chunks):
tcpdump -r large.pcap -w chunk_ -C 100
python3 HFL_PCAP_Analyzer.py chunk_*.pcap
```

**`Report not opening in browser`**
The report is saved to `REPORT/` beside the script. Use the `-r` flag for a custom path:
```bash
python3 HFL_PCAP_Analyzer.py capture.pcap -r ~/Desktop/report.html
```

**`No anomalies detected on known-malicious PCAP`**
- Verify the PCAP contains network-layer traffic (not just raw L2 frames)
- Run `--demo` first to confirm the engine works
- Ensure the capture includes the relevant attack phase (e.g., scanning PCAPs won't trigger C2 detections)

**Low threat score on obviously bad traffic**
The threat score is capped at 100 and the first hit of each detection method contributes. For bulk capture analysis with many repetitions, the score reflects the presence/absence of attack categories, not absolute incident severity.

---

## Security Notice

1. **Authorization required**: Only analyze network traffic for which you have explicit written authorization. Unauthorized interception of network communications is illegal in most jurisdictions.

2. **Data sensitivity**: PCAP files and generated reports contain sensitive network topology, credentials, and host information. Handle as confidential data. Store reports in access-controlled locations.

3. **Evidence integrity**: For forensic use, verify SHA-256 hash of input PCAP against chain-of-custody records before analysis. The report header displays the input file hash.

4. **Ethical use only**: This tool is provided for authorized security testing, incident response, threat hunting, and security research purposes only. Misuse to facilitate unauthorized access or privacy violations is prohibited.

5. **Report classification**: Treat generated reports as sensitive security information. The report header is labeled "FOR OFFICIAL USE ONLY."

---

## License

Copyright © 2025–2026 [HACKFORLAB](https://hackforlab.com/) — Threat Intelligence Labs  
All Rights Reserved.

This tool is provided for **authorized security use only**. Redistribution, resale, or use in unauthorized security assessments is prohibited without express written consent from [HACKFORLAB](https://hackforlab.com/).

---

*Built with ❤️ by [HACKFORLAB](https://hackforlab.com/) Threat Intelligence Labs*  
*For threat intelligence updates, detection signatures, and enterprise licensing: [hackforlab.com](https://hackforlab.com/)*