#!/usr/bin/env python3
"""
HFL PCAP ANALYZER v2.1 -- NBAD DETECTION ENGINE
HACKFORLAB -- Threat Intelligence Labs
566-Port Threat Intel | 80+ Detection Methods | 60+ NBAD Attack Classes

Enterprise-grade Network Behavior Anomaly Detection (NBAD) platform.
Pure Python -- zero external dependencies for core analysis.

NBAD DETECTION COVERAGE (60+ Attack Classes):
  RECONNAISSANCE:    TCP/UDP port scans, stealth scans (FIN/NULL/XMAS), OS fingerprinting,
                     network sweeps, SNMP/SMB/LDAP/WMI enumeration, DNS zone transfer,
                     OSINT probing, banner grabbing, service version probing
  C2 / BEACONING:    Periodic beaconing (CV<0.20), IRC/HTTP/HTTPS/DNS/ICMP C2,
                     DGA activity (entropy>3.5), fast-flux DNS, Tor, JA3/JARM anomalies,
                     C2 framework ports, domain fronting, long-lived sessions
  MALWARE PORTS:     566 ports / 568 malware families from HFL Threat Intel DB
                     (11 categories: Threat Actor/Rootkit/Ransomware/Backdoor/
                      Botnet/Trojan/Worm/Spyware/Malware/P2P/Phishing Campaign)
  DATA EXFILTRATION: Large transfers, high-rate exfil, DNS/ICMP/HTTP tunneling,
                     FTP exfil, SMTP data leaks, slow-drip, encoded payload,
                     steganography indicators, cloud storage abuse
  DENIAL OF SERVICE: SYN/UDP/ICMP/HTTP flood, DNS/NTP/SSDP/Memcached amplification,
                     Slowloris, fragmentation flood, application-layer DoS
  LATERAL MOVEMENT:  SMB/RDP/SSH/WMI/PsExec lateral, Pass-the-Hash,
                     Kerberoasting, WinRM, DCOM, token relay, PrintNightmare
  EXPLOITATION:      SQLi, command/code injection, directory traversal, Shellshock,
                     Log4Shell, ProxyShell, Spring4Shell, XXE, SSRF, deserialization
  CREDENTIAL ATTACKS: SSH/HTTP/RDP/FTP/SMB/LDAP brute force, password spray,
                      credential stuffing, default creds, Kerberos AS-REP roasting
  LAYER 2 ATTACKS:   ARP spoofing/poisoning, ARP scan, MAC flooding, VLAN hopping,
                     STP manipulation, CDP/LLDP abuse, DHCP starvation
  CLEARTEXT:         FTP, Telnet, HTTP POST, POP3, IMAP, SNMP v1/v2c, LDAP,
                     HTTP Basic Auth, NTLMv1
  PROTOCOL ANOMALY:  Deprecated TLS/SSL, invalid TCP flags, oversized DNS,
                     GRE/VXLAN tunneling, SOCKS proxy, HTTP CONNECT, fragmentation,
                     TTL anomalies, IP options abuse, port knocking patterns
  RANSOMWARE:        DragonForce/Datacarry/Crypto24 C2, encryption sweeps,
                     shadow copy deletion, rapid file encryption patterns
  THREAT ACTORS:     APT28, APT36, UNC5174, UAC-0226, UTG-Q-015, STEALC V2,
                     W3LL Phishing Kit, China-nexus APT
  RAT FAMILIES:      NjRAT, AsyncRAT, QuasarRAT, RemcosRAT, XWorm, DarkComet,
                     DarkTrack, Gh0st, NanoCore, Netwire, WarzoneRAT, PoisonIvy,
                     Sliver, Empire, CobaltStrike, Metasploit, PupyRAT, SparkRAT

REPORT OUTPUT:
  Reports are automatically saved to a REPORT/ folder created beside this script.
  Filename format: HFL_YYYYMMDD_HHMMSS_<pcap_name>.html

USAGE:
  python3 HFL_PCAP_Analyzer.py                          # Launch GUI
  python3 HFL_PCAP_Analyzer.py capture.pcap             # Single file (any path)
  python3 HFL_PCAP_Analyzer.py /any/path/cap.pcap       # Absolute path
  python3 HFL_PCAP_Analyzer.py /path/to/pcaps/          # Entire directory
  python3 HFL_PCAP_Analyzer.py *.pcap                   # Glob pattern
  python3 HFL_PCAP_Analyzer.py "D:\\captures\\*.pcap"   # Windows glob
  python3 HFL_PCAP_Analyzer.py cap.pcap -r custom.html  # Custom report path
  python3 HFL_PCAP_Analyzer.py cap.pcap --json          # JSON to stdout
  python3 HFL_PCAP_Analyzer.py --demo                   # Demo PCAP + analyze

MITRE ATT&CK: T1046 T1071 T1041 T1498 T1021 T1190 T1557 T1110 T1040
              T1600 T1219 T1571 T1486 T1568 T1090 T1095 T1048 T1550
              T1558 T1572 T1499 T1570 T1014 T1590 T1592 T1087 T1135

Author: HACKFORLAB -- Threat Intelligence Labs
Version: 2.1.0
"""

import sys, os, re, json, hashlib, math, time, struct, socket, argparse
import io, gzip, threading, ipaddress, collections
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter, defaultdict, OrderedDict
from typing import Optional, Dict, List, Tuple, Any, Set

VERSION = "2.1.0"
TOOL_NAME = "HFL PCAP Analyzer"
BRAND = "HACKFORLAB"
BRAND_URL = "https://hackforlab.com/"
BRAND_LINK = '<a href="https://hackforlab.com/" target="_blank" style="color:inherit;text-decoration:underline">HACKFORLAB</a>'

# ═══════════════════════════════════════════════════════════════════════════════
# PROTOCOL CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

PCAP_MAGIC_LE    = 0xa1b2c3d4   # Standard little-endian
PCAP_MAGIC_BE    = 0xd4c3b2a1   # Standard big-endian
PCAP_MAGIC_NS_LE = 0xa1b23c4d   # Nanosecond little-endian
PCAP_MAGIC_NS_BE = 0x4d3cb2a1   # Nanosecond big-endian
PCAPNG_MAGIC     = 0x0a0d0d0a   # PCAPNG section header block

# All known PCAP magic variants (modified/airopcap/old-wireshark etc.)
PCAP_MAGIC_VARIANTS = {
    0xa1b2c3d4,  # Standard LE
    0xd4c3b2a1,  # Standard BE
    0xa1b23c4d,  # Nanosecond LE
    0x4d3cb2a1,  # Nanosecond BE
    0xa1b2cd34,  # Modified/AirPcap variant (older Wireshark, AiroPcap)
    0x34cdb2a1,  # Modified BE
    0xa1b2c34d,  # Rare modified LE
    0x4dc3b2a1,  # Rare modified BE
}
PCAP_MAGIC_BE_SET  = {0xd4c3b2a1, 0x4d3cb2a1, 0x34cdb2a1, 0x4dc3b2a1}
PCAP_MAGIC_NS_SET  = {0xa1b23c4d, 0x4d3cb2a1}

ETHERTYPES = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86DD: 'IPv6', 0x8100: 'VLAN', 0x88CC: 'LLDP'}

IP_PROTOCOLS = {
    1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6-encap',
    47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 132: 'SCTP',
}

WELL_KNOWN_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP-S', 68: 'DHCP-C', 69: 'TFTP', 80: 'HTTP',
    88: 'Kerberos', 110: 'POP3', 119: 'NNTP', 123: 'NTP', 135: 'RPC',
    137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN', 143: 'IMAP',
    161: 'SNMP', 162: 'SNMP-Trap', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
    465: 'SMTPS', 500: 'IKE', 514: 'Syslog', 515: 'LPD', 520: 'RIP',
    587: 'SMTP-Sub', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1080: 'SOCKS', 1433: 'MSSQL', 1434: 'MSSQL-Mon', 1521: 'Oracle',
    1723: 'PPTP', 2049: 'NFS', 3268: 'GlobalCatalog', 3306: 'MySQL',
    3389: 'RDP', 3478: 'STUN', 4444: 'Metasploit', 4443: 'HTTPS-Alt',
    5060: 'SIP', 5061: 'SIPS', 5222: 'XMPP', 5432: 'PostgreSQL',
    5900: 'VNC', 5901: 'VNC-1', 5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS',
    6379: 'Redis', 6667: 'IRC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    8888: 'HTTP-Alt2', 9001: 'Tor-C2', 9050: 'Tor-SOCKS', 9150: 'Tor-Browser',
    9200: 'Elasticsearch', 9300: 'ES-Transport', 27017: 'MongoDB', 47001: 'WinRM',
}

DNS_TYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
    16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 43: 'DS',
    46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 65: 'HTTPS', 255: 'ANY',
    252: 'AXFR', 251: 'IXFR',
}

TLS_VERSIONS = {
    0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3',
    0x0300: 'SSL 3.0', 0x0200: 'SSL 2.0',
}

DEPRECATED_TLS = {0x0300, 0x0301, 0x0302, 0x0200}

HTTP_METHODS = {b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH', b'CONNECT', b'TRACE'}

PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'), ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'), ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('255.255.255.255/32'),
]

COLORS = {
    'bg_dark': '#0a0e1a', 'bg_mid': '#111827', 'bg_card': '#1a2332',
    'bg_input': '#0f1629', 'border': '#2a3a4a', 'accent': '#3b82f6',
    'accent_hover': '#2563eb', 'text': '#e2e8f0', 'text_secondary': '#94a3b8',
    'text_muted': '#64748b', 'green': '#22c55e', 'yellow': '#f59e0b',
    'orange': '#f97316', 'red': '#ef4444', 'critical': '#dc2626',
    'purple': '#a855f7', 'cyan': '#06b6d4', 'white': '#ffffff',
}

# ═══════════════════════════════════════════════════════════════════════════════
# HFL THREAT INTELLIGENCE — 566 MALICIOUS PORTS DATABASE
# Source: HFL PORT-Analysis Threat Intel Feed | 11 Adversary Categories
# ═══════════════════════════════════════════════════════════════════════════════

MALICIOUS_PORTS_DB = {
    21: {"names": ['CC Invader', 'Blade Runner', 'The Flu', 'Back Construction', 'Cattivik FTP Server', 'Dark FTP', 'Doly Trojan', 'Fore', 'Invisible FTP', 'Juggernaut 42', 'Larva', 'MotIv FTP', 'Net Administrator', 'Ramen', 'Senna Spy FTP server', 'Traitor 21', 'WinCrash'], "types": ['Malware']},
    23: {"names": ['EliteWrap'], "types": ['Malware']},
    31: {"names": ['Agent 31 Hackers', 'Paradise Masters'], "types": ['Malware']},
    80: {"names": ['Codered'], "types": ['Malware']},
    113: {"names": ['Shiver', 'Dosh', 'Cyn', 'Alicia', 'ADM worm', 'DataSpy Network X', 'Gibbon', 'Taskman'], "types": ['Malware']},
    135: {"names": ['Botnet CnC'], "types": ['Botnet']},
    137: {"names": ['W32/Korgo'], "types": ['Worm']},
    139: {"names": ['W32/Korgo'], "types": ['Worm']},
    161: {"names": ['W32/Deloder'], "types": ['Worm']},
    420: {"names": ['Breach'], "types": ['Malware']},
    443: {"names": ['Pushdo'], "types": ['Botnet']},
    445: {"names": ['W32/Deloder'], "types": ['Worm']},
    666: {"names": ['Ripper'], "types": ['Malware']},
    1001: {"names": ['Silencer'], "types": ['Malware']},
    1010: {"names": ['Doly Trojan'], "types": ['Malware']},
    1011: {"names": ['Doly Trojan'], "types": ['Malware']},
    1012: {"names": ['Doly Trojan'], "types": ['Malware']},
    1015: {"names": ['Doly Trojan'], "types": ['Malware']},
    1016: {"names": ['Doly Trojan'], "types": ['Malware']},
    1020: {"names": ['Vampire'], "types": ['Malware']},
    1024: {"names": ['NetSpy', 'Lithium', 'Latinus', 'Ptakks', 'Conficker'], "types": ['Malware', 'Worm']},
    1025: {"names": ['Ptakks', 'KiLo', 'Optix Pro', 'Real 2000', 'Remote Explorer Y2K', 'Remote Storm', 'Yajing', 'DataSpy Network X', 'AcidkoR', 'BDDT', 'Fraggle Rock', 'MuSka52', 'NetSpy', 'Paltalk', 'Remote Anything', 'RemoteNC', 'Conficker'], "types": ['Malware', 'Worm']},
    1026: {"names": ['RSM', 'Remote Explorer 2000', 'Dosh', 'DataSpy Network X', 'BDDT', 'Dark IRC', 'Delta Remote Access', 'Duddie', 'IRC Contact', 'RUX The TIc.K', 'Conficker'], "types": ['Malware', 'Worm']},
    1027: {"names": ['KiLo', 'Clandestine', 'DataSpy Network X', 'UandMe', 'Conficker'], "types": ['Malware', 'Worm']},
    1028: {"names": ['KiLo', 'SubSARI', 'KWM', 'Gibbon', 'DataSpy Network X', 'Dosh', 'Litmus', 'Paltalk', 'Conficker'], "types": ['Malware', 'Worm']},
    1029: {"names": ['SubSARI', 'Litmus', 'Clandestine', 'KWM', 'Conficker'], "types": ['Malware', 'Worm']},
    1030: {"names": ['Gibbon', 'KWM', 'Conficker'], "types": ['Malware', 'Worm']},
    1031: {"names": ['Xot', 'Xanadu', 'KWM', 'Little Witch', 'Conficker'], "types": ['Malware', 'Worm']},
    1032: {"names": ['Akosch4', 'Dosh', 'KWM', 'Conficker'], "types": ['Malware', 'Worm']},
    1033: {"names": ['Little Witch', 'Dosh', 'KWM', 'Net Advance', 'Conficker', 'Blaster', 'Zotob'], "types": ['Malware', 'Worm']},
    1034: {"names": ['KWM', 'Conficker', 'Nachi (Welchia)', 'Warzone RAT'], "types": ['Malware', 'Worm', 'Spyware']},
    1035: {"names": ['RemoteNC', 'Dosh', 'KWM', 'Truva Atl', 'Conficker', 'Nachi (Welchia)', 'Warzone RAT'], "types": ['Malware', 'Worm', 'Spyware']},
    1036: {"names": ['KWM', 'Nachi (Welchia)', 'Warzone RAT'], "types": ['Malware', 'Worm', 'Spyware']},
    1037: {"names": ['KWM', 'Arctic', 'Dosh', 'MoSucker', 'Nachi (Welchia)', 'Warzone RAT'], "types": ['Malware', 'Worm', 'Spyware']},
    1038: {"names": ['Nachi (Welchia)'], "types": ['Worm']},
    1039: {"names": ['Dosh'], "types": ['Malware']},
    1041: {"names": ['Dosh', 'RemoteNC'], "types": ['Malware']},
    1042: {"names": ['BLA trojan', 'DarkComet'], "types": ['Malware', 'Spyware']},
    1043: {"names": ['Dosh'], "types": ['Malware']},
    1044: {"names": ['Ptakks'], "types": ['Malware']},
    1049: {"names": ['Delf', 'The Hobbit Daemon'], "types": ['Malware']},
    1052: {"names": ['Slapper', 'Fire HacKer', 'The Hobbit Daemon'], "types": ['Malware']},
    1053: {"names": ['The Thief'], "types": ['Malware']},
    1054: {"names": ['AckCmd', 'RemoteNC'], "types": ['Malware']},
    1080: {"names": ['Bagle', 'Hesperbot', 'Andromeda'], "types": ['Worm', 'Trojan']},
    1095: {"names": ['Hvl RAT', 'Blood Fest Evolution', 'Remote Administration Tool - RAT'], "types": ['Malware']},
    1097: {"names": ['Hvl RAT', 'Blood Fest Evolution', 'Remote Administration Tool - RAT', 'APT36', 'T0rn Rootkit'], "types": ['Malware', 'Threat Actor', 'Rootkit']},
    1098: {"names": ['Hvl RAT', 'Blood Fest Evolution', 'Remote Administration Tool - RAT'], "types": ['Malware']},
    1099: {"names": ['Hvl RAT', 'Blood Fest Evolution', 'Remote Administration Tool - RAT', 'Hesperbot'], "types": ['Malware', 'Trojan']},
    1104: {"names": ['RexxRave'], "types": ['Malware']},
    1111: {"names": ['Daodan', 'Ultors Trojan', 'Mariposa'], "types": ['Malware', 'Trojan']},
    1115: {"names": ['Lurker', 'Protoss'], "types": ['Malware']},
    1116: {"names": ['Lurker'], "types": ['Malware']},
    1120: {"names": ['Net Bus'], "types": ['Malware']},
    1122: {"names": ['Last 2000', 'Singularity'], "types": ['Malware']},
    1130: {"names": ['Hesperbot'], "types": ['Trojan']},
    1150: {"names": ['Orion'], "types": ['Malware']},
    1151: {"names": ['Orion'], "types": ['Malware']},
    1170: {"names": ['Psyber Stream', 'Psyber Stream Server', 'Voice'], "types": ['Malware']},
    1177: {"names": ['Xtreme RAT', 'njRAT', 'Imminent Monitor'], "types": ['Spyware']},
    1180: {"names": ['Blackshades'], "types": ['Spyware']},
    1183: {"names": ['Cyn', 'SweetHeart'], "types": ['Malware']},
    1200: {"names": ['NoBackO'], "types": ['Malware']},
    1201: {"names": ['NoBackO'], "types": ['Malware']},
    1207: {"names": ['SoftWAR'], "types": ['Malware']},
    1212: {"names": ['Kaos'], "types": ['Malware']},
    1214: {"names": ['Kazaa'], "types": ['P2P']},
    1215: {"names": ['Force'], "types": ['Malware']},
    1218: {"names": ['Force'], "types": ['Malware']},
    1219: {"names": ['Force'], "types": ['Malware']},
    1234: {"names": ['Valvo line', 'KiLo', 'Ultors Trojan', 'NanoCore', 'Zeus', 'Zeus C2', 'Gh0st RAT'], "types": ['Malware', 'Spyware', 'Trojan']},
    1243: {"names": ['Sub Seven', 'SubSeven', 'BackDoor-G', 'Tiles'], "types": ['Malware']},
    1256: {"names": ['Spark RAT', 'RexxRave', 'Project nEXT', 'Xeno RAT', 'CurlBack RAT'], "types": ['Malware']},
    1272: {"names": ['The Matrix'], "types": ['Malware']},
    1337: {"names": ['NanoCore', 'Sliver C2', 'Covenant C2', 'Andromeda C2', 'Kaiten C2', 'Datacarry Ransomware'], "types": ['Spyware', 'Malware', 'Ransomware']},
    1350: {"names": ['Ramnit', 'TrickBot', 'Mebroot', 'Sub7', 'Stuxnet', 'Rustock', 'TDSS', 'FU Rootkit', 'Knark', 'Adore', 'Azazel', 'SuckIT', 'OSX Rootkit'], "types": ['Trojan', 'Rootkit']},
    1386: {"names": ['Dagger'], "types": ['Malware']},
    1415: {"names": ['Last 2000', 'Singularity'], "types": ['Malware']},
    1433: {"names": ['Kelihos'], "types": ['Trojan']},
    1434: {"names": ['SQL Slammer'], "types": ['Worm']},
    1445: {"names": ['Datacarry Ransomware'], "types": ['Ransomware']},
    1492: {"names": ['FTP99CMP'], "types": ['Malware']},
    1560: {"names": ['Big Gluck', 'Duddie'], "types": ['Malware']},
    1561: {"names": ['MuSka52'], "types": ['Malware']},
    1600: {"names": ['Shivka-Burka'], "types": ['Malware']},
    1604: {"names": ['DarkComet', 'Xtreme RAT', 'Quasar RAT', 'njRAT', 'Bandook', 'DarkTrack RAT'], "types": ['Spyware']},
    1711: {"names": ['yoyo'], "types": ['Malware']},
    1772: {"names": ['NetControle'], "types": ['Malware']},
    1777: {"names": ['Scarab'], "types": ['Malware']},
    1807: {"names": ['SpySender'], "types": ['Malware']},
    1826: {"names": ['Senna Spy Trojan Generator', 'Duddie', 'Glacier', 'Der Spaeher', 'Protoss', 'Singularity', 'Trojan Cow'], "types": ['Malware']},
    1833: {"names": ['TCC'], "types": ['Malware']},
    1834: {"names": ['TCC'], "types": ['Malware']},
    1835: {"names": ['TCC'], "types": ['Malware']},
    1836: {"names": ['TCC'], "types": ['Malware']},
    1837: {"names": ['TCC'], "types": ['Malware']},
    1911: {"names": ['Arctic'], "types": ['Malware']},
    1967: {"names": ['For Your Eyes Only', 'WM FTP Server'], "types": ['Malware']},
    1978: {"names": ['Slapper'], "types": ['Malware']},
    1981: {"names": ['Shockrave', 'Bowl'], "types": ['Malware']},
    1984: {"names": ['Intruzzo', 'Q-taz', 'Xtreme RAT'], "types": ['Malware', 'Spyware']},
    1985: {"names": ['Black Diver', 'Q-taz'], "types": ['Malware']},
    1991: {"names": ['DarkTrack RAT'], "types": ['Spyware']},
    1999: {"names": ['BackDoor 1.00-1.03', 'SubSeven', 'Back Door', 'TransScout'], "types": ['Malware']},
    2000: {"names": ['Remote Explorer 2000', 'GOTHIC Intruder', 'Real 2000', 'Remote Explorer Y2K', 'Fear', 'A-trojan', 'Der Spaeher', 'Force', 'Last 2000', 'Senna Spy Trojan Generator', 'Way', 'Singularity'], "types": ['Malware']},
    2001: {"names": ['Trojan Cow', 'Scalper', 'Senna Spy Trojan Generator', 'Glacier', 'Der Spaeher', 'Duddie', 'Protoss', 'Singularity', 'CodeRed II', 'DragonForce', 'DragonForce Ransomware'], "types": ['Malware', 'Worm', 'Ransomware']},
    2002: {"names": ['Slapper', 'Senna Spy Trojan Generator', 'Duddie', 'Sensive', 'CodeRed II', 'Sobig.F'], "types": ['Malware', 'Worm']},
    2003: {"names": ['CodeRed II', 'Sobig.F'], "types": ['Worm']},
    2023: {"names": ['Ripper Pro', 'Ripper'], "types": ['Malware']},
    2086: {"names": ['UNC5174', 'unc5174'], "types": ['Threat Actor']},
    2115: {"names": ['Bugs'], "types": ['Malware']},
    2130: {"names": ['Mini BackLash'], "types": ['Malware']},
    2140: {"names": ['Deep Throat', 'Invasor', 'The Invasor', 'Foreplay'], "types": ['Malware']},
    2156: {"names": ['Oracle'], "types": ['Malware']},
    2222: {"names": ['SweetHeart', 'Way', 'SpyNote', 'Mariposa', 'Emotet', 'ZeroAccess', 'Empire C2', 'unc5174', 'Datacarry Ransomware'], "types": ['Malware', 'Spyware', 'Trojan', 'Rootkit', 'Threat Actor', 'Ransomware']},
    2281: {"names": ['Nautical'], "types": ['Malware']},
    2300: {"names": ['Storm'], "types": ['Malware']},
    2311: {"names": ['Studio 54'], "types": ['Malware']},
    2332: {"names": ['IRC Contact', 'Silent Spy'], "types": ['Malware']},
    2334: {"names": ['IRC Contact', 'Power'], "types": ['Malware']},
    2337: {"names": ['IRC Contact', 'The Hobbit Daemon'], "types": ['Malware']},
    2339: {"names": ['Voice Spy', 'IRC Contact'], "types": ['Malware']},
    2343: {"names": ['Asylum'], "types": ['Malware']},
    2345: {"names": ['Pupy RAT'], "types": ['Spyware']},
    2404: {"names": ['NjRAT', 'Remcos RAT', 'AsyncRAT', 'Quasar RAT', 'Remcos'], "types": ['Malware', 'Spyware']},
    2407: {"names": ['yoyo'], "types": ['Malware']},
    2500: {"names": ['Gozi'], "types": ['Trojan']},
    2555: {"names": ['li0n', 'T0rn Rootkit'], "types": ['Malware']},
    2589: {"names": ['Dagger'], "types": ['Malware']},
    2702: {"names": ['Black Diver'], "types": ['Malware']},
    2745: {"names": ['Bagle', 'Phatbot', 'Agobot', 'Rbot', 'Gaobot', 'Dabber'], "types": ['Worm']},
    2773: {"names": ['SubSeven', 'SubSeven 2.1 Gold'], "types": ['Malware']},
    2774: {"names": ['SubSeven', 'SubSeven 2.1 Gold'], "types": ['Malware']},
    2800: {"names": ['Theef'], "types": ['Malware']},
    2801: {"names": ['Phineas Phucker'], "types": ['Malware']},
    2983: {"names": ['Breach'], "types": ['Malware']},
    2989: {"names": ['Rat backdoor', 'Remote Administration Tool - RAT'], "types": ['Malware']},
    3000: {"names": ['Remote Shut', 'InetSpy', 'Theef', 'Xtreme RAT', 'Remcos', 'Adwind RAT', 'Gozi'], "types": ['Malware', 'Spyware', 'Trojan']},
    3001: {"names": ['DragonForce', 'DragonForce Ransomware'], "types": ['Ransomware', 'Rootkit']},
    3006: {"names": ['Clandestine'], "types": ['Malware']},
    3024: {"names": ['WinCrash'], "types": ['Malware']},
    3100: {"names": ['Remcos'], "types": ['Spyware']},
    3127: {"names": ['Mydoom', 'Bagle', 'W32.Lovgate'], "types": ['Worm']},
    3128: {"names": ['Reverse WWW Tunnel Backdoor', 'RingZero', 'Dridex', 'Hpingbot'], "types": ['Malware', 'Trojan']},
    3129: {"names": ['Masters Paradise'], "types": ['Malware']},
    3131: {"names": ['SubSari'], "types": ['Malware']},
    3132: {"names": ['Zeus'], "types": ['Trojan']},
    3150: {"names": ['Deep Throat', 'Invasor', 'The Invasor', 'Foreplay', 'Mini BackLash'], "types": ['Malware']},
    3176: {"names": ['Blackshades'], "types": ['Spyware']},
    3215: {"names": ['XHX', 'BlackStar', 'Ghost'], "types": ['Malware']},
    3240: {"names": ['UAC_0226'], "types": ['Malware', 'Threat Actor']},
    3292: {"names": ['Xposure'], "types": ['Malware']},
    3295: {"names": ['Xposure'], "types": ['Malware']},
    3306: {"names": ['Kelihos', 'Banload'], "types": ['Trojan']},
    3333: {"names": ['Daodan', 'Ramnit', 'Zeus Panda', 'Datacarry Ransomware'], "types": ['Malware', 'Trojan', 'Ransomware']},
    3389: {"names": ['Dridex'], "types": ['Trojan']},
    3393: {"names": ['NjRAT', 'Remcos RAT', 'AsyncRAT', 'Quasar RAT'], "types": ['Malware']},
    3417: {"names": ['Xposure'], "types": ['Malware']},
    3418: {"names": ['Xposure'], "types": ['Malware']},
    3456: {"names": ['Force', 'Fear', 'Terror trojan'], "types": ['Malware']},
    3459: {"names": ['Eclipse 2000', 'Sanctuary'], "types": ['Malware']},
    3460: {"names": ['Poison Ivy'], "types": ['Spyware']},
    3461: {"names": ['Poison Ivy'], "types": ['Spyware']},
    3462: {"names": ['Poison Ivy'], "types": ['Spyware']},
    3500: {"names": ['Remcos'], "types": ['Spyware']},
    3700: {"names": ['Portal of Doom'], "types": ['Malware']},
    3721: {"names": ['Whirlpool'], "types": ['Malware']},
    3723: {"names": ['Mantis'], "types": ['Malware']},
    3980: {"names": ['Remcos RAT'], "types": ['Malware']},
    3996: {"names": ['Remote Anything', 'SkyDance'], "types": ['Malware']},
    3997: {"names": ['Remote Anything', 'SkyDance'], "types": ['Malware']},
    3999: {"names": ['Remote Anything', 'SkyDance'], "types": ['Malware']},
    4000: {"names": ['RA', 'Remote Anything', 'SkyDance', 'Storm Worm'], "types": ['Malware', 'Worm']},
    4001: {"names": ['DragonForce Ransomware'], "types": ['Ransomware']},
    4092: {"names": ['WinCrash'], "types": ['Malware']},
    4128: {"names": ['RedShad'], "types": ['Malware']},
    4156: {"names": ['Slapper'], "types": ['Malware']},
    4201: {"names": ['War trojan'], "types": ['Malware']},
    4225: {"names": ['Silent Spy'], "types": ['Malware']},
    4226: {"names": ['XWorm C2'], "types": ['Malware']},
    4315: {"names": ['Power'], "types": ['Malware']},
    4321: {"names": ['BoBo', 'Schoolbus 1.0 trojans'], "types": ['Malware']},
    4433: {"names": ['Waledac', 'Pupy RAT', 'Kelihos', 'Ramnit', 'Zeus Panda', 'SpyEye', 'Banload', 'Netwire', 'Fynloski', 'Stuxnet', 'Mariposa', 'Emotet', 'Gozi', 'TrickBot', 'Andromeda', 'APT28'], "types": ['Worm', 'Spyware', 'Trojan']},
    4434: {"names": ['Waledac', 'SpyEye'], "types": ['Worm', 'Trojan']},
    4435: {"names": ['Waledac'], "types": ['Worm']},
    4442: {"names": ['Oracle'], "types": ['Malware']},
    4443: {"names": ['W3LL_Phishing_Kit'], "types": ['Threat Actor']},
    4444: {"names": ['trojans or METASPLOIT', 'Anubis Backdoor', 'Prosiak', 'CrackDown', 'Oracle', 'Swift Remote', 'Blaster (MSBlast)', 'Blaster', 'Gaobot', 'Adwind RAT', 'PlugX', 'CrossRAT', 'Waledac', 'Zeus Panda', 'Kelihos V3', 'Fynloski', 'Stuxnet', 'Zeus', 'Alureon (TDL-4)', 'Datacarry Ransomware'], "types": ['Malware', 'Backdoor', 'Worm', 'Spyware', 'Trojan', 'Rootkit', 'Ransomware']},
    4445: {"names": ['Oracle'], "types": ['Malware']},
    4447: {"names": ['Oracle'], "types": ['Malware']},
    4449: {"names": ['Oracle'], "types": ['Malware']},
    4451: {"names": ['Oracle'], "types": ['Malware']},
    4455: {"names": ['Kelihos V3'], "types": ['Trojan']},
    4545: {"names": ['Blackshades'], "types": ['Spyware']},
    4567: {"names": ['File Nail 1'], "types": ['Malware']},
    4590: {"names": ['ICQTrojan'], "types": ['Malware']},
    4653: {"names": ['Cero'], "types": ['Malware']},
    4700: {"names": ['Theef'], "types": ['Malware']},
    4782: {"names": ['Quasar RAT'], "types": ['Spyware']},
    4783: {"names": ['Quasar RAT'], "types": ['Spyware']},
    4836: {"names": ['Power'], "types": ['Malware']},
    4950: {"names": ['ICQ Trojan'], "types": ['Malware']},
    5000: {"names": ['Bubbel', 'Gorilla Botnet C2', 'Ra1d', 'Back Door Setup', 'Sockets des Troie', 'Rbot', 'Athena RAT', 'Waledac', 'Ice IX', 'Emotet', 'TrickBot'], "types": ['Malware', 'Worm', 'Spyware', 'Trojan']},
    5001: {"names": ['Sockets de Troie', 'Back Door Setup', 'Sockets des Troie', 'DragonForce Ransomware'], "types": ['Malware', 'Ransomware']},
    5002: {"names": ['Shaft'], "types": ['Malware']},
    5050: {"names": ['GravityRAT', 'Crypto24'], "types": ['Spyware', 'Ransomware']},
    5051: {"names": ['GravityRAT'], "types": ['Malware']},
    5060: {"names": ['Netwire', 'Dridex'], "types": ['Trojan']},
    5077: {"names": ['GravityRAT'], "types": ['Spyware']},
    5099: {"names": ['GravityRAT'], "types": ['Spyware']},
    5135: {"names": ['Bmail'], "types": ['Malware']},
    5150: {"names": ['Pizza'], "types": ['Malware']},
    5155: {"names": ['Oracle'], "types": ['Malware']},
    5250: {"names": ['Pizza'], "types": ['Malware']},
    5321: {"names": ['Firehotcker'], "types": ['Malware']},
    5350: {"names": ['Pizza'], "types": ['Malware']},
    5353: {"names": ['Sliver C2'], "types": ['Malware']},
    5377: {"names": ['Iani'], "types": ['Malware']},
    5400: {"names": ['Blade Runner 0.80 Alpha', 'Blade Runner', 'Back Construction', 'Digital Spy'], "types": ['Malware']},
    5401: {"names": ['Blade Runner 0.80 Alpha', 'Blade Runner', 'Digital Spy', 'Back Construction', 'Mneah'], "types": ['Malware']},
    5402: {"names": ['Blade Runner 0.80 Alpha', 'Blade Runner', 'Digital Spy', 'Back Construction', 'Mneah'], "types": ['Malware']},
    5419: {"names": ['DarkSky'], "types": ['Malware']},
    5430: {"names": ['Net Advance'], "types": ['Malware']},
    5450: {"names": ['Pizza'], "types": ['Malware']},
    5500: {"names": ['Ramnit'], "types": ['Trojan']},
    5503: {"names": ['Remote Shell'], "types": ['Malware']},
    5534: {"names": ['CC Invader', 'Blade Runner', 'The Flu', 'Back Construction', 'Cattivik FTP Server', 'Dark FTP', 'Doly Trojan', 'Fore', 'Invisible FTP', 'Juggernaut 42', 'Larva', 'MotIv FTP', 'Net Administrator', 'Ramen', 'Senna Spy FTP server', 'Traitor 21', 'WinCrash'], "types": ['Malware']},
    5550: {"names": ['Pizza'], "types": ['Malware']},
    5552: {"names": ['njRAT', 'DarkTrack RAT'], "types": ['Spyware']},
    5554: {"names": ['W32/Sasser', 'Phatbot', 'Agobot', 'Fizzer', 'Spybot', 'Gaobot', 'Dabber'], "types": ['Worm']},
    5555: {"names": ['Daodan', 'NetSpy (DK)', 'NoXcape', 'Anubis Backdoor', 'SpyNote', 'Adwind RAT', 'Kelihos', 'Zeus', 'ZeroAccess', 'AndroRAT'], "types": ['Malware', 'Backdoor', 'Spyware', 'Trojan', 'Rootkit']},
    5556: {"names": ['BO Facil'], "types": ['Malware']},
    5557: {"names": ['BO Facil'], "types": ['Malware']},
    5569: {"names": ['Robo-Hack'], "types": ['Malware']},
    5650: {"names": ['Pizza', 'Remcos RAT'], "types": ['Malware']},
    5669: {"names": ['SpArTa'], "types": ['Malware']},
    5678: {"names": ['CrossRAT'], "types": ['Spyware']},
    5679: {"names": ['Nautical'], "types": ['Malware']},
    5742: {"names": ['WinCrash'], "types": ['Malware']},
    5800: {"names": ['W32/Agobot'], "types": ['Worm']},
    5882: {"names": ['Y3K RAT'], "types": ['Malware']},
    5888: {"names": ['Y3K RAT'], "types": ['Malware']},
    5900: {"names": ['W32/Agobot'], "types": ['Worm']},
    6000: {"names": ['NetBus', 'Aladino', 'The Thing', 'XWORM'], "types": ['Malware']},
    6001: {"names": ['DragonForce Ransomware'], "types": ['Ransomware']},
    6006: {"names": ['Bad Blood'], "types": ['Malware']},
    6112: {"names": ['SubSeven'], "types": ['Botnet']},
    6267: {"names": ['GW Girl'], "types": ['Malware']},
    6346: {"names": ['Gnutella'], "types": ['Malware']},
    6400: {"names": ['The Thing', 'Thing'], "types": ['Malware']},
    6500: {"names": ['Athena RAT'], "types": ['Spyware', 'Trojan']},
    6501: {"names": ['UAC_0226'], "types": ['Malware', 'Threat Actor']},
    6521: {"names": ['Oracle'], "types": ['Malware']},
    6666: {"names": ['KiLo', 'AL-Bareki', 'SpArTa', 'NjRAT', 'Remcos RAT', 'AsyncRAT', 'Quasar RAT', 'Uloader', 'CloudEyE', 'unc5174'], "types": ['Malware', 'Threat Actor']},
    6667: {"names": ['Various IRC Bots', 'Trinity intruder-to-master and master-to-daemon SubSeven server (default for V2.1 Icqfix and beyond)', 'Bionet', 'KiLo', 'Trinity', 'Trinity master-to-daemon', 'Dark FTP', 'DataSpy Network X', 'Acropolis', 'BlackRat', 'Dark IRC', 'Gunsan', 'InCommand', 'Kaitex', 'Laocoon', 'Net-Devil', 'Reverse Trojan', 'ScheduleAgent', 'SlackBot', 'SubSeven', 'Subseven 2.1.4 DefCon 8', 'Y3K RAT', 'Kaiten C2'], "types": ['Botnet', 'Malware']},
    6669: {"names": ['Vampire', 'Host Control', 'Voyager Alpha Force'], "types": ['Malware']},
    6670: {"names": ['Deep Throat', 'DeepThroat', 'Foreplay', 'BackWeb Server', 'WinNuke eXtreame'], "types": ['Malware']},
    6697: {"names": ['Force'], "types": ['Malware']},
    6711: {"names": ['Sub Seven', 'BackDoor-G', 'Duddie- KiLo', 'Little Witch', 'Netkey', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'VP Killer', 'KiLo', 'Duddie', 'UandMe'], "types": ['Malware']},
    6712: {"names": ['Spadeace', 'Funny trojan', 'KiLo', 'SubSeven'], "types": ['Malware']},
    6713: {"names": ['KiLo', 'SubSeven'], "types": ['Malware']},
    6714: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    6715: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    6718: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    6766: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    6767: {"names": ['KiLo', 'NetSpy (DK)', 'Pasana', 'UandMe'], "types": ['Malware']},
    6771: {"names": ['DeepThroat', 'Deep Throat', 'Foreplay'], "types": ['Malware']},
    6776: {"names": ['Sub Seven', 'VP Killer', 'SubSeven', '2000 Cracks', 'BackDoor-G'], "types": ['Malware']},
    6777: {"names": ['Bagle'], "types": ['Worm']},
    6789: {"names": ['CrossRAT'], "types": ['Spyware']},
    6838: {"names": ['Mstream'], "types": ['Malware']},
    6881: {"names": ['BitTorrent'], "types": ['P2P']},
    6891: {"names": ['Force'], "types": ['Malware']},
    6892: {"names": ['Blackshades'], "types": ['Spyware']},
    6969: {"names": ['BitTorrent Tracker', 'GateCrash', 'GateCrasher', 'Kid Terror', 'Dark IRC', '2000 Cracks', 'BlitzNet', 'Laphex', 'Net Controller', 'SpArTa', 'Vagr Nocker', 'Tsunami C2', 'Kaiten C2'], "types": ['P2P', 'Malware']},
    7000: {"names": ['Remote Grab', 'SubSeven 2.1 Gold', 'Aladino', 'Gunsan', 'SubSeven', 'Theef', 'Stuxnet', 'APT28', 'Remcos RAT', 'XWORM'], "types": ['Malware', 'Trojan']},
    7007: {"names": ['Silent Spy'], "types": ['Malware']},
    7070: {"names": ['PlugX', 'PlugX C2', 'Gh0st RAT C2'], "types": ['Spyware', 'Malware']},
    7215: {"names": ['SubSeven', 'SubSeven 2.1 Gold'], "types": ['Malware']},
    7284: {"names": ['Swan Vector'], "types": ['Malware']},
    7300: {"names": ['Net Spy', 'NetMonitor'], "types": ['Malware']},
    7301: {"names": ['NetMonitor'], "types": ['Malware']},
    7306: {"names": ['NetMonitor'], "types": ['Malware']},
    7307: {"names": ['NetMonitor', 'NetSpy', 'Remote Process Monitor'], "types": ['Malware']},
    7308: {"names": ['NetMonitor', 'NetSpy', 'X Spy'], "types": ['Malware']},
    7340: {"names": ['Myth Stealer'], "types": ['Malware']},
    7424: {"names": ['Host Control'], "types": ['Malware']},
    7597: {"names": ['Qaz', 'QAZ.A', 'Qaz.Trojan', 'note.com', 'QAZ.worm', 'TROJ_QAZ.A', 'Trojan/Notepad', 'W32.HLLW.Qaz.A'], "types": ['Malware']},
    7626: {"names": ['Gdoor', 'Senna Spy Trojan Generator', 'Duddie', 'Glacier', 'Der Spaeher', 'Protoss', 'Singularity', 'Trojan Cow'], "types": ['Malware']},
    7648: {"names": ['BlackStar', 'XHX', 'Ghost'], "types": ['Malware']},
    7702: {"names": ['ViperSoftX malware'], "types": ['Malware']},
    7711: {"names": ['Aurotun Stealer'], "types": ['Malware']},
    7712: {"names": ['Gorilla Botnet C2', 'Aurotun Stealer'], "types": ['Malware']},
    7713: {"names": ['Aurotun Stealer'], "types": ['Malware']},
    7714: {"names": ['Aurotun Stealer'], "types": ['Malware']},
    7718: {"names": ['Senna Spy Trojan Generator', 'Duddie', 'Glacier', 'Der Spaeher', 'Protoss', 'Singularity', 'Trojan Cow'], "types": ['Malware']},
    7722: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    7777: {"names": ['GodMsg'], "types": ['Malware']},
    7788: {"names": ['Singularity', 'Last 2000'], "types": ['Malware']},
    7789: {"names": ['ICKiller'], "types": ['Malware']},
    7871: {"names": ['Storm Worm'], "types": ['Worm']},
    7872: {"names": ['Storm Worm'], "types": ['Worm']},
    7873: {"names": ['Storm Worm'], "types": ['Worm']},
    7983: {"names": ['Mstream'], "types": ['Malware']},
    8000: {"names": ['NanoCore', 'njRAT'], "types": ['Spyware']},
    8001: {"names": ['DragonForce Ransomware'], "types": ['Ransomware']},
    8011: {"names": ['Way'], "types": ['Malware']},
    8012: {"names": ['Ptakks'], "types": ['Malware']},
    8080: {"names": ['DarkComet', 'Adwind RAT', 'PlugX', 'Kelihos', 'Ramnit', 'Waledac', 'Zeus Panda', 'Kelihos V3', 'SpyEye', 'Banload', 'Netwire', 'Ice IX', 'Fynloski', 'Stuxnet', 'Mariposa', 'Zeus', 'Emotet', 'TrickBot', 'Hesperbot', 'Dridex', 'Andromeda', 'APT28'], "types": ['Spyware', 'Trojan']},
    8081: {"names": ['Zeus Panda', 'SpyEye', 'Banload', 'Stuxnet', 'APT28'], "types": ['Trojan']},
    8082: {"names": ['TheMoon'], "types": ['Worm']},
    8088: {"names": ['SpyEye', 'Ice IX', 'Mariposa'], "types": ['Trojan']},
    8090: {"names": ["Aphex's Remote Packet Sniffer"], "types": ['Malware']},
    8110: {"names": ['DLP'], "types": ['Malware']},
    8111: {"names": ['DLP'], "types": ['Malware']},
    8127: {"names": ['9_119', 'Chonker'], "types": ['Malware']},
    8130: {"names": ['Chonker', '9_119', 'DLP'], "types": ['Malware']},
    8131: {"names": ['DLP'], "types": ['Malware']},
    8181: {"names": ['DarkComet RAT'], "types": ['Botnet']},
    8301: {"names": ['DLP'], "types": ['Malware']},
    8302: {"names": ['DLP'], "types": ['Malware']},
    8322: {"names": ['DLP'], "types": ['Malware']},
    8329: {"names": ['DLP'], "types": ['Malware']},
    8444: {"names": ['RedELK C2'], "types": ['Malware']},
    8488: {"names": ['KiLo'], "types": ['Malware']},
    8489: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    8585: {"names": ['Turkojan'], "types": ['Spyware']},
    8593: {"names": ['Blackshades'], "types": ['Spyware']},
    8787: {"names": ['BackOfrice 2000'], "types": ['Malware']},
    8811: {"names": ['Force', 'Fear', 'Terror trojan'], "types": ['Malware']},
    8821: {"names": ['Dosh', 'Cyn', 'Alicia', 'ADM worm', 'DataSpy Network X', 'Gibbon', 'Taskman'], "types": ['Malware']},
    8848: {"names": ['Whirlpool'], "types": ['Malware']},
    8864: {"names": ['Whirlpool'], "types": ['Malware']},
    8866: {"names": ['Bagle', 'Phatbot', 'Agobot', 'Sobig.F', 'Rbot', 'Gaobot'], "types": ['Worm']},
    8887: {"names": ['UNC5174', 'unc5174'], "types": ['Threat Actor']},
    8888: {"names": ['NjRAT', 'Remcos RAT', 'AsyncRAT', 'Quasar RAT', 'Fizzer', 'Spybot', 'Zotob', 'SpyNote', 'Imminent Monitor', 'Athena RAT', 'Fynloski', 'TrickBot', 'APT28', 'Sliver C2', 'UNC5174', 'unc5174'], "types": ['Malware', 'Worm', 'Spyware', 'Trojan', 'Threat Actor']},
    8998: {"names": ['Sobig'], "types": ['Worm']},
    9000: {"names": ['Waledac', 'Netwire', 'Ice IX', 'Hesperbot', 'Andromeda'], "types": ['Trojan']},
    9001: {"names": ['DarkComet', 'Pupy RAT', 'Kelihos V3', 'Netwire', 'Fynloski', 'Emotet', 'Dridex', 'Uloader', 'CloudEyE', 'DragonForce Ransomware', 'Datacarry Ransomware'], "types": ['Spyware', 'Trojan', 'Malware', 'Ransomware']},
    9090: {"names": ['Gozi', 'Andromeda', 'Andromeda C2', 'Gozi C2'], "types": ['Trojan', 'Malware']},
    9148: {"names": ['Nautical'], "types": ['Malware']},
    9301: {"names": ['DLP'], "types": ['Malware']},
    9325: {"names": ['Mstream'], "types": ['Malware']},
    9329: {"names": ['DLP'], "types": ['Malware']},
    9536: {"names": ['Lula'], "types": ['Malware']},
    9561: {"names": ['Crat Pro'], "types": ['Malware']},
    9563: {"names": ['Crat Pro'], "types": ['Malware']},
    9872: {"names": ['Portal of Doom'], "types": ['Malware']},
    9873: {"names": ['Portal of Doom'], "types": ['Malware']},
    9874: {"names": ['Portal of Doom'], "types": ['Malware']},
    9875: {"names": ['Portal of Doom'], "types": ['Malware']},
    9876: {"names": ['Rux'], "types": ['Malware']},
    9878: {"names": ['Small Big Brother', 'TransScout'], "types": ['Malware']},
    9898: {"names": ['Dabber'], "types": ['Worm']},
    9899: {"names": ['Dabber'], "types": ['Worm']},
    9988: {"names": ['Rbot', 'Gaobot'], "types": ['Worm']},
    9989: {"names": ['iNi-Killer'], "types": ['Malware']},
    9996: {"names": ['Sasser'], "types": ['Worm']},
    9999: {"names": ['Phatbot', 'Agobot', 'Blaster', 'Zotob', 'PlugX'], "types": ['Worm', 'Spyware']},
    10000: {"names": ['XHX', 'TCP Door', 'Oracle'], "types": ['Malware']},
    10001: {"names": ['DTr', 'Lula', 'DragonForce Ransomware'], "types": ['Malware', 'Ransomware']},
    10002: {"names": ['Lula'], "types": ['Malware']},
    10003: {"names": ['Lula'], "types": ['Malware']},
    10012: {"names": ['Amanda'], "types": ['Malware']},
    10013: {"names": ['Amanda'], "types": ['Malware']},
    10048: {"names": ['Delf'], "types": ['Malware']},
    10067: {"names": ['Portal of Doom'], "types": ['Malware']},
    10080: {"names": ['Mydoom'], "types": ['Worm']},
    10084: {"names": ['Syphillis'], "types": ['Malware']},
    10100: {"names": ['Gift', 'Slapper', 'GiFt trojan', 'Control Total', 'Scalper'], "types": ['Malware']},
    10128: {"names": ['Docker Exploit'], "types": ['Malware']},
    10167: {"names": ['Portal of Doom'], "types": ['Malware']},
    10168: {"names": ['W32.Lovgate'], "types": ['Worm']},
    10234: {"names": ['Conficker'], "types": ['Worm']},
    10498: {"names": ['Mstream'], "types": ['Malware']},
    10607: {"names": ['Coma 1.0.9', 'Coma'], "types": ['Malware']},
    10666: {"names": ['Ambush'], "types": ['Malware']},
    11000: {"names": ['Senna Spy', 'DataRape', 'Senna Spy Trojan Generator'], "types": ['Malware']},
    11011: {"names": ['Amanda'], "types": ['Malware']},
    11111: {"names": ['Breach'], "types": ['Malware']},
    11223: {"names": ['Progenic trojan', 'Secret Agent'], "types": ['Malware']},
    11225: {"names": ['Cyn', 'Cyn.120', 'Cyn.100', 'Cyn.103', 'Cyn.210'], "types": ['Malware']},
    11831: {"names": ['Pest', 'DataRape', 'DarkFace', 'Latinus', 'Vagr Nocker'], "types": ['Malware']},
    12223: {"names": ['HackÂ´99 KeyLogger'], "types": ['Malware']},
    12321: {"names": ['Protoss'], "types": ['Malware']},
    12345: {"names": ['NetBus', 'Valvo line', 'BlueIce 2000', 'GabanBus', 'Pie Bill Gates', 'NetBus 1.x', 'X-Bill', 'Mypic', 'Ashley', 'Q-taz', 'Sensive', 'Snape', 'Vagr Nocker', 'ValvNet', 'Whack Job', 'Fizzer', 'W32.Lovgate', 'Rbot', 'Spybot', 'Turkojan', 'Bandook'], "types": ['Botnet', 'Malware', 'Worm', 'Spyware']},
    12346: {"names": ['NetBus 1.x', 'GabanBus', 'NetBus'], "types": ['Malware']},
    12349: {"names": ['Bionet', 'The Saint'], "types": ['Malware']},
    12361: {"names": ['Whack-a-mole'], "types": ['Malware']},
    12362: {"names": ['Whack-a-mole'], "types": ['Malware']},
    12623: {"names": ['ButtMan', 'DUN Control'], "types": ['Malware']},
    12624: {"names": ['ButtMan', 'Power'], "types": ['Malware']},
    12684: {"names": ['Power'], "types": ['Malware']},
    12904: {"names": ['Akropolis.100', 'Rocks', 'Rocks.100'], "types": ['Malware']},
    13370: {"names": ['SpArTa'], "types": ['Malware']},
    13389: {"names": ['UTG-Q-015'], "types": ['Threat Actor']},
    13500: {"names": ['Theef'], "types": ['Malware']},
    14884: {"names": ['STEALC V2'], "types": ['Threat Actor']},
    15000: {"names": ['In Route to the Hell', 'R0xr4t'], "types": ['Malware']},
    15206: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    15207: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    15210: {"names": ['remote shell backdoor server', 'UDP remote shell backdoor server'], "types": ['Malware']},
    15382: {"names": ['SubZero', 'SubZero.100', 'Cyn.121', 'Cyn.101', 'Cyn', 'Cyn.104', 'Cyn.211'], "types": ['Malware']},
    15485: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    15486: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    15512: {"names": ['Iani'], "types": ['Malware']},
    15845: {"names": ['KiLo'], "types": ['Malware']},
    16080: {"names": ['Pushdo'], "types": ['Botnet']},
    16514: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    16515: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    16660: {"names": ['Stacheldraht intruder-to-master'], "types": ['Malware']},
    16712: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    16959: {"names": ['SubSeven', 'Subseven 2.1.4 DefCon 8'], "types": ['Malware']},
    16969: {"names": ['Priority'], "types": ['Malware']},
    17166: {"names": ['Mosaic'], "types": ['Malware']},
    17241: {"names": ['APT36'], "types": ['Threat Actor']},
    17777: {"names": ['Orion'], "types": ['Malware']},
    18000: {"names": ['Signal Messenger'], "types": ['Phishing Campaign']},
    18006: {"names": ['Back Orifice 2000'], "types": ['Malware']},
    18753: {"names": ['Shaft master-to-daemon', 'Shaft'], "types": ['Malware']},
    19821: {"names": ['APT36'], "types": ['Threat Actor']},
    20000: {"names": ['PSYcho Files', 'Millenium', 'XHX', 'W32.Lovgate', 'Bandook'], "types": ['Malware', 'Worm', 'Spyware']},
    20001: {"names": ['Millennium', 'Millenium', 'Insect', 'PSYcho Files'], "types": ['Malware']},
    20002: {"names": ['AcidkoR', 'PSYcho Files'], "types": ['Malware']},
    20023: {"names": ['VP Killer'], "types": ['Malware']},
    20034: {"names": ['NetBus 2 Pro', 'NetBus 2.0', 'Beta-NetBus 2.01', 'NetBus 2.0 Pro Hidden', 'NetBus 2.0 Pro', 'Whack Job'], "types": ['Malware']},
    20432: {"names": ['Shaft intruder-to-master', 'Shaft'], "types": ['Malware']},
    20433: {"names": ['Shaft daemon-to-master', 'Shaft'], "types": ['Malware']},
    21544: {"names": ['Girl Friend', 'GirlFriend 1.0', 'Beta-1.35', 'Schwindler', 'Exploiter', 'GirlFriend', 'Kid Terror', 'FreddyK', 'Sensive', 'Winsp00fer'], "types": ['Malware']},
    21579: {"names": ['Breach'], "types": ['Malware']},
    21817: {"names": ['APT36'], "types": ['Threat Actor']},
    22115: {"names": ['Cyn.122', 'Cyn.102', 'Cyn', 'Cyn.105', 'Cyn.212'], "types": ['Malware']},
    22222: {"names": ['Rux', 'Prosiak', 'Ruler', 'G.R.O.B.', 'Donald Dick', 'RUX The TIc.K'], "types": ['Malware']},
    22456: {"names": ['Clandestine'], "types": ['Malware']},
    23005: {"names": ['NetTrash', 'Oxon'], "types": ['Malware']},
    23006: {"names": ['NetTrash', 'Oxon'], "types": ['Malware']},
    23023: {"names": ['Logged'], "types": ['Malware']},
    23032: {"names": ['Amanda'], "types": ['Malware']},
    23221: {"names": ['APT36'], "types": ['Threat Actor']},
    23432: {"names": ['Asylum', 'Asylum.014', 'Asylum.012', 'Asylum.010', 'Asylum.013', 'MiniAsylum.110'], "types": ['Malware']},
    23456: {"names": ['Evil FTP', 'Ugly FTP', 'Vagr Nocker', 'Clandestine', 'Whack Job'], "types": ['Malware']},
    23476: {"names": ['Donald Dick'], "types": ['Malware']},
    23477: {"names": ['Donald Dick'], "types": ['Malware']},
    25002: {"names": ['MOTD'], "types": ['Malware']},
    25685: {"names": ['Moon Pie'], "types": ['Malware']},
    25686: {"names": ['DarkFace', 'MoonPie'], "types": ['Malware']},
    25885: {"names": ['MOTD'], "types": ['Malware']},
    25902: {"names": ['Noodlophile Malware'], "types": ['Malware']},
    25982: {"names": ['DarkFace', 'MoonPie'], "types": ['Malware']},
    26274: {"names": ['Delta', 'Delta Source'], "types": ['Malware']},
    27015: {"names": ['Remcos'], "types": ['Spyware']},
    27017: {"names": ['Banload'], "types": ['Trojan']},
    27184: {"names": ['Alvgus trojan 2000'], "types": ['Malware']},
    27373: {"names": ['Charge'], "types": ['Malware']},
    27374: {"names": ['SubSeven', 'SubSeven server (default for V2.1-Defcon)', 'Sub Seven', 'Seeker', 'li0n', 'Bad Blood', 'Fake SubSeven', 'Ramen', 'SubSeven 2.1 Gold', 'Subseven 2.1.4 DefCon 8', 'SubSeven 2.2', 'SubSeven Muie', 'The Saint', 'Spybot'], "types": ['Botnet', 'Malware', 'Worm']},
    27375: {"names": ['NjRAT', 'Remcos RAT', 'AsyncRAT', 'Quasar RAT'], "types": ['Malware']},
    27425: {"names": ['APT36'], "types": ['Threat Actor']},
    27444: {"names": ['Trinoo master-to-daemon', 'Trinoo'], "types": ['Malware']},
    27665: {"names": ['Trinoo intruder-to-master'], "types": ['Malware']},
    28218: {"names": ['Oracle'], "types": ['Malware']},
    29104: {"names": ['NETrojan', 'NetTrojan'], "types": ['Malware']},
    29559: {"names": ['AntiLamer BackDoor - DarkFace -DataRape -Ducktoy', 'Latinus', 'DataRape', 'AntiLamer BackDoor', 'DarkFace', 'Ducktoy', 'Pest', 'Vagr Nocker'], "types": ['Malware']},
    29589: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    29999: {"names": ['AntiLamer BackDoor'], "types": ['Malware']},
    30000: {"names": ['DataRape', 'Infector'], "types": ['Malware']},
    30005: {"names": ['Litmus'], "types": ['Malware']},
    30100: {"names": ['NetSphere', 'NetSphere 1.27a'], "types": ['Malware']},
    30101: {"names": ['NetSphere 1.27a'], "types": ['Malware']},
    30102: {"names": ['NetSphere 1.27a'], "types": ['Malware']},
    30103: {"names": ['NetSphere'], "types": ['Malware']},
    30700: {"names": ['Mantis'], "types": ['Malware']},
    31320: {"names": ['Little Witch'], "types": ['Malware']},
    31335: {"names": ['Trinoo daemon-to-master'], "types": ['Malware']},
    31337: {"names": ['Back Orifice', 'Deep BO', 'BlitzNet', 'Back Orifice (Lm)', 'ADM worm', 'Back Fire', 'Back Orifice russian', 'BO client', 'BO Facil', 'BO2', 'Freak88', 'Freak2k', 'NoBackO', 'Back Orifice 1.20 patches', 'Baron Night', 'Beeone', 'BO spy', 'Sockdmini', 'icmp_pipe.c', 'Spybot'], "types": ['Botnet', 'Malware', 'Worm']},
    31338: {"names": ['Net Spy', 'Back Orifice', 'Deep BO', 'DeepBO', 'NetSpy (DK)', 'Butt Funnel'], "types": ['Malware']},
    31339: {"names": ['Net Spy', 'NetSpy DK', 'Little Witch', 'NetSpy (DK)'], "types": ['Malware']},
    31340: {"names": ['Little Witch'], "types": ['Malware']},
    31382: {"names": ['NetSpy', 'Lithium', 'Latinus', 'Ptakks'], "types": ['Malware']},
    31415: {"names": ['NetSpy', 'Lithium', 'Latinus', 'Ptakks'], "types": ['Malware']},
    31416: {"names": ['Lithium', 'NetSpy', 'Latinus', 'Ptakks'], "types": ['Malware']},
    31557: {"names": ['Xanadu', 'Xanadu.110'], "types": ['Malware']},
    31666: {"names": ['BOWhack'], "types": ['Malware']},
    31789: {"names": ['Hack a Tack'], "types": ['Malware']},
    31791: {"names": ['Hack a Tack'], "types": ['Malware']},
    32001: {"names": ['Donald Dick'], "types": ['Malware']},
    32100: {"names": ['Peanut Brittle', 'Project nEXT'], "types": ['Malware']},
    32791: {"names": ['Acropolis', 'Rocks'], "types": ['Malware']},
    33270: {"names": ['Trinity master-to-daemon', 'Trinity'], "types": ['Malware']},
    33333: {"names": ['Prosiak'], "types": ['Malware']},
    33567: {"names": ['Backdoor rootshell via inetd (from Lion worm)', 'li0n', 'T0rn Rootkit'], "types": ['Malware']},
    33568: {"names": ['Trojaned version of SSH (from Lion worm)', 'li0n', 'T0rn Rootkit'], "types": ['Malware']},
    33911: {"names": ['Spirit 2000', 'Spirit 2001'], "types": ['Malware']},
    34312: {"names": ['Delf'], "types": ['Malware']},
    34313: {"names": ['Delf'], "types": ['Malware']},
    34324: {"names": ['BigGluck'], "types": ['Malware']},
    34343: {"names": ['Osiris'], "types": ['Malware']},
    34444: {"names": ['Donald Dick'], "types": ['Malware']},
    34555: {"names": ['Trinoo (for Windows)'], "types": ['Malware']},
    35555: {"names": ['Trinoo (for Windows)'], "types": ['Malware']},
    37237: {"names": ['Mantis'], "types": ['Malware']},
    37651: {"names": ['Charge'], "types": ['Malware']},
    40101: {"names": ['Aurotun Stealer'], "types": ['Malware']},
    40105: {"names": ['Aurotun Stealer'], "types": ['Malware']},
    40412: {"names": ['The Spy'], "types": ['Malware']},
    40421: {"names": ['Masters Paradise Trojan horse', 'Masters Paradise', 'Agent 40421'], "types": ['Malware']},
    40422: {"names": ['Masters Paradise'], "types": ['Malware']},
    40423: {"names": ['Masters Paradise'], "types": ['Malware']},
    40426: {"names": ['Masters Paradise'], "types": ['Malware']},
    41337: {"names": ['Storm', 'Back Orifice russian'], "types": ['Malware']},
    42323: {"names": ['UNC5174', 'unc5174'], "types": ['Threat Actor']},
    43720: {"names": ['KiLo'], "types": ['Malware']},
    44014: {"names": ['Iani'], "types": ['Malware']},
    44444: {"names": ['Prosiak', 'Turkojan'], "types": ['Malware', 'Spyware']},
    44767: {"names": ['School Bus'], "types": ['Malware']},
    45092: {"names": ['T0rn Rootkit'], "types": ['Rootkit']},
    45454: {"names": ['Osiris'], "types": ['Malware']},
    45673: {"names": ['Acropolis', 'Rocks'], "types": ['Malware']},
    46666: {"names": ['Taskman'], "types": ['Malware']},
    47198: {"names": ['UTG-Q-015'], "types": ['Threat Actor']},
    47262: {"names": ['Delta', 'Delta Source'], "types": ['Malware']},
    47698: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    47785: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    47891: {"names": ['AntiLamer BackDoor'], "types": ['Malware']},
    48512: {"names": ['Arctic'], "types": ['Malware']},
    48905: {"names": ['NjRAT', 'Remcos RAT', 'AsyncRAT', 'Quasar RAT'], "types": ['Malware']},
    49683: {"names": ['Fenster'], "types": ['Malware']},
    49698: {"names": ['KiLo'], "types": ['Malware']},
    50130: {"names": ['Enterprise'], "types": ['Malware']},
    50505: {"names": ['Sockets de Troie'], "types": ['Malware']},
    50766: {"names": ['Fore'], "types": ['Malware']},
    50829: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    51234: {"names": ['Cyn.123', 'Cyn.103', 'Cyn', 'Cyn.106', 'Cyn.213'], "types": ['Malware']},
    51598: {"names": ['XWorm C2'], "types": ['Malware']},
    51820: {"names": ['Sliver C2'], "types": ['Malware']},
    51966: {"names": ['T0rn Rootkit'], "types": ['Rootkit']},
    52365: {"names": ['Way'], "types": ['Malware']},
    52901: {"names": ['Omega'], "types": ['Malware']},
    53001: {"names": ['Remote Windows Shutdown'], "types": ['Malware']},
    53795: {"names": ['XWorm C2'], "types": ['Malware']},
    54283: {"names": ['SubSeven', 'SubSeven 2.1 Gold', 'Sub7'], "types": ['Malware', 'Rootkit']},
    54321: {"names": ['SchoolBus .69-1.11', 'School Bus', 'Back Orifice 2000', 'yoyo', 'Imminent Monitor'], "types": ['Malware', 'Spyware']},
    55665: {"names": ['Latinus', 'Pinochet'], "types": ['Malware']},
    55666: {"names": ['Latinus', 'Pinochet'], "types": ['Malware']},
    56003: {"names": ['ViperSoftX malware'], "types": ['Malware']},
    56004: {"names": ['ViperSoftX malware'], "types": ['Malware']},
    56005: {"names": ['ViperSoftX malware'], "types": ['Malware']},
    56565: {"names": ['Osiris'], "types": ['Malware']},
    58134: {"names": ['Charge'], "types": ['Malware']},
    59999: {"names": ['China-nexus APT'], "types": ['Threat Actor']},
    60000: {"names": ['Foreplay', 'Deep Throat', 'Sockets des Troie'], "types": ['Malware']},
    60001: {"names": ['Trinity', 'Trinity master-to-daemon'], "types": ['Malware']},
    60008: {"names": ['Backdoor rootshel via inetd (from Lion worm)', 'li0n', 'T0rn Rootkit', 'Sub7'], "types": ['Malware', 'Rootkit']},
    60411: {"names": ['Connection'], "types": ['Malware']},
    61337: {"names": ['Nota'], "types": ['Malware']},
    61440: {"names": ['Orion'], "types": ['Malware']},
    61466: {"names": ['Telecommando'], "types": ['Malware']},
    61746: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    61747: {"names": ['KiLo', 'Netkey', 'BackDoor-G', 'Duddie', 'Little Witch', 'Spadeace', 'SubSARI', 'SubSeven', 'SweetHeart', 'UandMe', 'VP Killer'], "types": ['Malware']},
    61748: {"names": ['KiLo'], "types": ['Malware']},
    64666: {"names": ['RSM'], "types": ['Malware']},
    65000: {"names": ['Stacheldraht master-to-daemon', 'Devil', 'Sockets des Troie', 'Stacheldraht'], "types": ['Malware']},
    65289: {"names": ['yoyo'], "types": ['Malware']},
    65421: {"names": ['Dosh', 'Cyn', 'Alicia', 'ADM worm', 'DataSpy Network X', 'Gibbon', 'Taskman'], "types": ['Malware']},
    65422: {"names": ['Dosh', 'Cyn', 'Alicia', 'ADM worm', 'DataSpy Network X', 'Gibbon', 'Taskman'], "types": ['Malware']},
    65432: {"names": ['The Traitor (= th3tr41t0r)'], "types": ['Malware']},
    65530: {"names": ['Windows Mite'], "types": ['Malware']},
}

# Severity classification
HIGH_SEVERITY_TYPES = {"Threat Actor", "Rootkit", "Ransomware", "Backdoor"}
MEDIUM_SEVERITY_TYPES = {"Botnet", "Trojan", "Spyware", "Worm", "Malware", "Phishing Campaign"}

C2_FRAMEWORK_PORTS = [1042, 1177, 1337, 1604, 2222, 2404, 3000, 3100, 3393, 3500, 3980, 4226, 4444, 4782, 4783, 5353, 5552, 5650, 6000, 6666, 7000, 8000, 8080, 8181, 8888, 9001, 27015, 27375, 48905, 51598, 51820, 53795]
RANSOMWARE_PORTS = [1337, 1445, 2001, 2222, 3001, 3333, 4001, 4444, 5001, 5050, 6001, 8001, 9001, 10001]
THREAT_ACTOR_PORTS = [1097, 2086, 2222, 3240, 4443, 6501, 6666, 8887, 8888, 13389, 14884, 17241, 19821, 21817, 23221, 27425, 42323, 47198, 59999]
ROOTKIT_PORTS = [1097, 1350, 2222, 3001, 4444, 5555, 45092, 51966, 54283, 60008]
BOTNET_PORTS = [135, 443, 6112, 6667, 8181, 12345, 16080, 27374, 31337]

# RAT family port signatures (multi-port matching)
RAT_FAMILIES = {
    "NjRAT":       {"ports": {3393, 2404, 27375, 48905, 8888, 1177}, "desc": "NjRAT/Bladabindi RAT"},
    "AsyncRAT":    {"ports": {6606, 7707, 8808, 8888, 7777}, "desc": "AsyncRAT remote access trojan"},
    "QuasarRAT":   {"ports": {4782, 4783, 1604, 7000}, "desc": "QuasarRAT open-source RAT"},
    "RemcosRAT":   {"ports": {3980, 2404, 7777, 5552}, "desc": "Remcos Pro RAT"},
    "XWorm":       {"ports": {7070, 3000, 4444, 5050, 8080}, "desc": "XWorm commodity RAT"},
    "DarkComet":   {"ports": {1604, 3000, 7799, 8192}, "desc": "DarkComet RAT"},
    "Sliver":      {"ports": {31337, 8888, 8443, 443, 80}, "desc": "Sliver C2 framework"},
    "CobaltStrike":{"ports": {50050, 4444, 8080, 8443, 443, 80, 2222}, "desc": "Cobalt Strike Beacon"},
    "HavocC2":     {"ports": {40056, 8443, 443}, "desc": "Havoc C2 framework"},
    "BruteRatel":  {"ports": {443, 8443, 7443}, "desc": "Brute Ratel C4 framework"},
    "Metasploit":  {"ports": {4444, 4445, 4446, 8443, 1234}, "desc": "Metasploit Framework"},
    "Mythic":      {"ports": {7443, 443, 80, 8080}, "desc": "Mythic C2 framework"},
}

def _is_private(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_RANGES)
    except:
        return False


def _esc(t):
    return str(t).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def _human_bytes(b):
    for u in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024: return f'{b:.1f} {u}'
        b /= 1024
    return f'{b:.1f} PB'


def _entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s: return 0.0
    freq = Counter(s.lower())
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in freq.values() if c > 0)


def _script_dir() -> str:
    """Return the directory that contains this script file."""
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        return os.getcwd()


def _report_dir() -> str:
    """Return (and create) the REPORT/ folder next to the script."""
    rd = os.path.join(_script_dir(), 'REPORT')
    os.makedirs(rd, exist_ok=True)
    return rd


def _report_filename(pcap_path: str) -> str:
    """
    Generate: REPORT/HFL_YYYYMMDD_HHMMSS_<pcap_stem>.html
    Always placed in the REPORT/ folder beside this script.
    """
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    stem = Path(pcap_path).stem if pcap_path else 'batch'
    stem = re.sub(r'[^\w\-]', '_', stem)[:50]
    return os.path.join(_report_dir(), f'HFL_{ts}_{stem}.html')

class PcapParser:
    """Pure-Python PCAP and PCAPNG file parser."""

    @staticmethod
    def parse(filepath: str) -> Dict[str, Any]:
        with open(filepath, 'rb') as f:
            header = f.read(16)
            if len(header) < 4:
                raise ValueError("File is too small to be a valid capture file")
            magic = struct.unpack('<I', header[:4])[0]

            # ── Standard PCAP (all known magic variants) ──────────────────
            if magic in PCAP_MAGIC_VARIANTS:
                f.seek(0)
                return PcapParser._parse_pcap(f, magic)

            # ── Try big-endian read of magic (some writers use BE even for LE) ──
            magic_be = struct.unpack('>I', header[:4])[0]
            if magic_be in PCAP_MAGIC_VARIANTS:
                f.seek(0)
                return PcapParser._parse_pcap(f, magic_be)

            # ── PCAPNG ────────────────────────────────────────────────────
            elif magic == PCAPNG_MAGIC:
                f.seek(0)
                return PcapParser._parse_pcapng(f)

            # ── Gzip-compressed capture (.pcap.gz / .pcapng.gz) ───────────
            elif header[:2] == b'\x1f\x8b':
                f.seek(0)
                try:
                    gz = gzip.GzipFile(fileobj=f)
                    inner_magic = struct.unpack('<I', gz.read(4))[0]
                    gz.seek(0)
                    if inner_magic in PCAP_MAGIC_VARIANTS:
                        return PcapParser._parse_pcap(gz, inner_magic)
                    elif inner_magic == PCAPNG_MAGIC:
                        return PcapParser._parse_pcapng(gz)
                    else:
                        raise ValueError(
                            f"Gzip-compressed file does not contain a valid PCAP/PCAPNG "
                            f"(inner magic: 0x{inner_magic:08x})")
                except (OSError, struct.error) as e:
                    raise ValueError(f"File appears gzip-compressed but cannot be read: {e}")

            # ── Helpful diagnostics for common non-pcap formats ───────────
            else:
                try:
                    sample = header + f.read(256)
                    text_sample = sample.decode('utf-8', errors='ignore')
                except Exception:
                    text_sample = ""

                hint = ""
                if all(b in (0x0a, 0x0d, 0x20, 0x09) or 0x20 <= b < 0x7f for b in header[:8]):
                    hint = (
                        " The file appears to be a TEXT export (e.g. Wireshark plain-text "
                        "or CSV). Re-export using 'File -> Save As' with format "
                        "'Wireshark/pcapng' or 'Wireshark/pcap'."
                    )
                elif magic == 0x7b0a2020 or header[:1] == b'{':
                    hint = " The file appears to be JSON, not a binary capture."
                elif header[:5] == b'<?xml' or header[:5] == b'<pdml':
                    hint = " The file appears to be XML/PDML, not a binary capture."
                else:
                    hint = (
                        f" Not a recognised PCAP variant. "
                        f"Known LE magic: {sorted(hex(m) for m in PCAP_MAGIC_VARIANTS)}. "
                        f"Try opening in Wireshark and re-exporting as standard pcap/pcapng."
                    )

                raise ValueError(
                    f"Unknown file format (magic: 0x{magic:08x}).{hint}"
                )

    @staticmethod
    def _parse_pcap(f, magic):
        is_be = magic in PCAP_MAGIC_BE_SET
        is_ns = magic in PCAP_MAGIC_NS_SET
        endian = '>' if is_be else '<'

        hdr = f.read(24)
        _, ver_maj, ver_min, tz, sigfigs, snaplen, linktype = struct.unpack(f'{endian}IHHiIII', hdr)

        packets = []
        pkt_idx = 0
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, cap_len, orig_len = struct.unpack(f'{endian}IIII', pkt_hdr)
            if is_ns:
                timestamp = ts_sec + ts_usec / 1e9
            else:
                timestamp = ts_sec + ts_usec / 1e6

            data = f.read(cap_len)
            if len(data) < cap_len:
                break

            packets.append({
                'index': pkt_idx,
                'timestamp': timestamp,
                'cap_len': cap_len,
                'orig_len': orig_len,
                'data': data,
                'linktype': linktype,
            })
            pkt_idx += 1

        return {
            'format': 'pcap',
            'version': f'{ver_maj}.{ver_min}',
            'snaplen': snaplen,
            'linktype': linktype,
            'packets': packets,
            'nanosecond': is_ns,
        }

    @staticmethod
    def _parse_pcapng(f):
        packets = []
        linktype = 1  # default Ethernet
        if_tsresol = 6  # default microsecond

        pkt_idx = 0
        while True:
            block_hdr = f.read(8)
            if len(block_hdr) < 8:
                break
            block_type, block_len = struct.unpack('<II', block_hdr)

            if block_len < 12:
                break

            body = f.read(block_len - 12)
            trail = f.read(4)  # trailing block length

            if block_type == 0x0A0D0D0A:  # Section Header Block
                pass
            elif block_type == 0x00000001:  # Interface Description Block
                if len(body) >= 4:
                    linktype = struct.unpack('<HH', body[:4])[0]
            elif block_type == 0x00000006:  # Enhanced Packet Block
                if len(body) >= 20:
                    iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack('<IIIII', body[:20])
                    timestamp = ((ts_high << 32) | ts_low) / (10 ** if_tsresol)
                    data = body[20:20 + cap_len]
                    packets.append({
                        'index': pkt_idx,
                        'timestamp': timestamp,
                        'cap_len': cap_len,
                        'orig_len': orig_len,
                        'data': data,
                        'linktype': linktype,
                    })
                    pkt_idx += 1
            elif block_type == 0x00000003:  # Simple Packet Block
                if len(body) >= 4:
                    orig_len = struct.unpack('<I', body[:4])[0]
                    data = body[4:]
                    packets.append({
                        'index': pkt_idx,
                        'timestamp': 0,
                        'cap_len': len(data),
                        'orig_len': orig_len,
                        'data': data,
                        'linktype': linktype,
                    })
                    pkt_idx += 1

        return {
            'format': 'pcapng',
            'version': '1.0',
            'snaplen': 0,
            'linktype': linktype,
            'packets': packets,
            'nanosecond': False,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# PROTOCOL DISSECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class ProtocolDissector:
    """Dissects packets into protocol layers."""

    @staticmethod
    def dissect(pkt: Dict) -> Dict:
        """Dissect a raw packet into protocol layers."""
        result = {
            'index': pkt['index'], 'timestamp': pkt['timestamp'],
            'cap_len': pkt['cap_len'], 'orig_len': pkt['orig_len'],
            'layers': [], 'ethernet': None, 'ip': None, 'transport': None,
            'app': None, 'summary': '',
        }

        data = pkt['data']
        linktype = pkt.get('linktype', 1)

        # Layer 2: Ethernet (linktype 1)
        if linktype == 1 and len(data) >= 14:
            eth = ProtocolDissector._parse_ethernet(data)
            result['ethernet'] = eth
            result['layers'].append('Ethernet')
            data = data[14:]

            # Handle VLAN tagging
            if eth['ethertype'] == 0x8100 and len(data) >= 4:
                vlan_id = struct.unpack('!H', data[:2])[0] & 0x0FFF
                eth['vlan_id'] = vlan_id
                eth['ethertype'] = struct.unpack('!H', data[2:4])[0]
                data = data[4:]

            # Layer 3
            if eth['ethertype'] == 0x0800:  # IPv4
                ip = ProtocolDissector._parse_ipv4(data)
                if ip:
                    result['ip'] = ip
                    result['layers'].append('IPv4')
                    ip_hdr_len = ip['ihl'] * 4
                    payload = data[ip_hdr_len:]

                    # Layer 4
                    if ip['protocol'] == 6:  # TCP
                        tcp = ProtocolDissector._parse_tcp(payload)
                        if tcp:
                            result['transport'] = tcp
                            result['layers'].append('TCP')
                            tcp_payload = payload[tcp['data_offset'] * 4:]
                            result['app'] = ProtocolDissector._identify_app(tcp['src_port'], tcp['dst_port'], tcp_payload, 'tcp')

                    elif ip['protocol'] == 17:  # UDP
                        udp = ProtocolDissector._parse_udp(payload)
                        if udp:
                            result['transport'] = udp
                            result['layers'].append('UDP')
                            udp_payload = payload[8:]
                            result['app'] = ProtocolDissector._identify_app(udp['src_port'], udp['dst_port'], udp_payload, 'udp')

                    elif ip['protocol'] == 1:  # ICMP
                        icmp = ProtocolDissector._parse_icmp(payload)
                        if icmp:
                            result['transport'] = icmp
                            result['layers'].append('ICMP')

            elif eth['ethertype'] == 0x0806:  # ARP
                arp = ProtocolDissector._parse_arp(data)
                if arp:
                    result['ip'] = arp
                    result['layers'].append('ARP')

            elif eth['ethertype'] == 0x86DD:  # IPv6
                ip6 = ProtocolDissector._parse_ipv6(data)
                if ip6:
                    result['ip'] = ip6
                    result['layers'].append('IPv6')
                    payload = data[40:]
                    if ip6['next_header'] == 6:
                        tcp = ProtocolDissector._parse_tcp(payload)
                        if tcp:
                            result['transport'] = tcp; result['layers'].append('TCP')
                            tcp_payload = payload[tcp['data_offset'] * 4:]
                            result['app'] = ProtocolDissector._identify_app(tcp['src_port'], tcp['dst_port'], tcp_payload, 'tcp')
                    elif ip6['next_header'] == 17:
                        udp = ProtocolDissector._parse_udp(payload)
                        if udp:
                            result['transport'] = udp; result['layers'].append('UDP')
                            result['app'] = ProtocolDissector._identify_app(udp['src_port'], udp['dst_port'], payload[8:], 'udp')

        # Raw IP (linktype 101)
        elif linktype == 101 and len(data) >= 20:
            version = (data[0] >> 4) & 0xF
            if version == 4:
                ip = ProtocolDissector._parse_ipv4(data)
                if ip:
                    result['ip'] = ip; result['layers'].append('IPv4')
                    payload = data[ip['ihl'] * 4:]
                    if ip['protocol'] == 6:
                        tcp = ProtocolDissector._parse_tcp(payload)
                        if tcp:
                            result['transport'] = tcp; result['layers'].append('TCP')
                            result['app'] = ProtocolDissector._identify_app(tcp['src_port'], tcp['dst_port'], payload[tcp['data_offset']*4:], 'tcp')
                    elif ip['protocol'] == 17:
                        udp = ProtocolDissector._parse_udp(payload)
                        if udp:
                            result['transport'] = udp; result['layers'].append('UDP')
                            result['app'] = ProtocolDissector._identify_app(udp['src_port'], udp['dst_port'], payload[8:], 'udp')

        # Build summary
        result['summary'] = ProtocolDissector._build_summary(result)
        return result

    @staticmethod
    def _parse_ethernet(data):
        dst = data[:6]; src = data[6:12]
        ethertype = struct.unpack('!H', data[12:14])[0]
        return {
            'dst_mac': ':'.join(f'{b:02x}' for b in dst),
            'src_mac': ':'.join(f'{b:02x}' for b in src),
            'ethertype': ethertype,
            'ethertype_name': ETHERTYPES.get(ethertype, f'0x{ethertype:04x}'),
            'type': 'ethernet',
        }

    @staticmethod
    def _parse_ipv4(data):
        if len(data) < 20: return None
        b0 = data[0]
        version = (b0 >> 4) & 0xF
        ihl = b0 & 0xF
        if version != 4 or ihl < 5: return None
        tos, total_len, ident, flags_frag, ttl, proto, checksum = struct.unpack('!xBHHHBBH', data[0:12])
        # Re-parse properly
        ihl = data[0] & 0xF
        tos = data[1]
        total_len = struct.unpack('!H', data[2:4])[0]
        ident = struct.unpack('!H', data[4:6])[0]
        flags_frag = struct.unpack('!H', data[6:8])[0]
        ttl = data[8]
        proto = data[9]
        checksum = struct.unpack('!H', data[10:12])[0]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        flags = (flags_frag >> 13) & 0x7
        frag_offset = flags_frag & 0x1FFF

        return {
            'type': 'ipv4', 'version': 4, 'ihl': ihl, 'tos': tos,
            'total_length': total_len, 'identification': ident,
            'flags': flags, 'fragment_offset': frag_offset,
            'ttl': ttl, 'protocol': proto,
            'protocol_name': IP_PROTOCOLS.get(proto, f'Proto-{proto}'),
            'checksum': checksum, 'src_ip': src_ip, 'dst_ip': dst_ip,
            'df': bool(flags & 0x2), 'mf': bool(flags & 0x1),
        }

    @staticmethod
    def _parse_ipv6(data):
        if len(data) < 40: return None
        vtcfl = struct.unpack('!I', data[:4])[0]
        version = (vtcfl >> 28) & 0xF
        if version != 6: return None
        payload_len = struct.unpack('!H', data[4:6])[0]
        next_header = data[6]
        hop_limit = data[7]
        src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
        return {
            'type': 'ipv6', 'version': 6, 'payload_length': payload_len,
            'next_header': next_header, 'hop_limit': hop_limit,
            'protocol': next_header,
            'protocol_name': IP_PROTOCOLS.get(next_header, f'Proto-{next_header}'),
            'src_ip': src_ip, 'dst_ip': dst_ip, 'ttl': hop_limit,
        }

    @staticmethod
    def _parse_tcp(data):
        if len(data) < 20: return None
        src_port, dst_port, seq, ack, offset_flags = struct.unpack('!HHIIH', data[:14])
        data_offset = (offset_flags >> 12) & 0xF
        flags = offset_flags & 0x3F
        window = struct.unpack('!H', data[14:16])[0]
        checksum = struct.unpack('!H', data[16:18])[0]
        urgent = struct.unpack('!H', data[18:20])[0]

        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')

        return {
            'type': 'tcp', 'src_port': src_port, 'dst_port': dst_port,
            'seq': seq, 'ack': ack, 'data_offset': data_offset,
            'flags': flags, 'flag_names': flag_names, 'flags_str': ','.join(flag_names),
            'window': window, 'checksum': checksum, 'urgent': urgent,
            'payload_len': max(0, len(data) - data_offset * 4),
            'src_port_name': WELL_KNOWN_PORTS.get(src_port, ''),
            'dst_port_name': WELL_KNOWN_PORTS.get(dst_port, ''),
        }

    @staticmethod
    def _parse_udp(data):
        if len(data) < 8: return None
        src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])
        return {
            'type': 'udp', 'src_port': src_port, 'dst_port': dst_port,
            'length': length, 'checksum': checksum,
            'payload_len': max(0, length - 8),
            'src_port_name': WELL_KNOWN_PORTS.get(src_port, ''),
            'dst_port_name': WELL_KNOWN_PORTS.get(dst_port, ''),
        }

    @staticmethod
    def _parse_icmp(data):
        if len(data) < 8: return None
        icmp_type, code, checksum, rest = struct.unpack('!BBHI', data[:8])
        type_names = {0: 'Echo Reply', 3: 'Dest Unreachable', 5: 'Redirect',
                      8: 'Echo Request', 11: 'Time Exceeded', 13: 'Timestamp', 14: 'Timestamp Reply'}
        return {
            'type': 'icmp', 'icmp_type': icmp_type, 'code': code,
            'checksum': checksum, 'type_name': type_names.get(icmp_type, f'Type-{icmp_type}'),
            'payload_len': len(data) - 8,
        }

    @staticmethod
    def _parse_arp(data):
        if len(data) < 28: return None
        hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack('!HHBBH', data[:8])
        sender_mac = ':'.join(f'{b:02x}' for b in data[8:14])
        sender_ip = socket.inet_ntoa(data[14:18])
        target_mac = ':'.join(f'{b:02x}' for b in data[18:24])
        target_ip = socket.inet_ntoa(data[24:28])
        op_names = {1: 'Request', 2: 'Reply'}
        return {
            'type': 'arp', 'opcode': opcode, 'opcode_name': op_names.get(opcode, f'Op-{opcode}'),
            'sender_mac': sender_mac, 'sender_ip': sender_ip,
            'target_mac': target_mac, 'target_ip': target_ip,
            'src_ip': sender_ip, 'dst_ip': target_ip,
        }

    @staticmethod
    def _identify_app(src_port, dst_port, payload, transport):
        """Identify application-layer protocol from ports and payload."""
        app = {'protocol': 'unknown', 'details': {}}
        ports = {src_port, dst_port}
        min_port = min(src_port, dst_port)

        # DNS
        if 53 in ports and transport == 'udp' and len(payload) >= 12:
            dns = ProtocolDissector._parse_dns(payload)
            if dns: return dns

        # HTTP
        if payload and len(payload) > 4:
            first_word = payload.split(b' ', 1)[0] if b' ' in payload[:12] else b''
            if first_word in HTTP_METHODS:
                return ProtocolDissector._parse_http_request(payload)
            if payload[:5] == b'HTTP/':
                return ProtocolDissector._parse_http_response(payload)

        # TLS
        if len(payload) >= 5 and payload[0] == 0x16:
            tls = ProtocolDissector._parse_tls(payload)
            if tls: return tls

        # Port-based identification
        if 443 in ports or 8443 in ports:
            app['protocol'] = 'TLS/HTTPS'
        elif 80 in ports or 8080 in ports:
            app['protocol'] = 'HTTP'
        elif 22 in ports:
            app['protocol'] = 'SSH'
        elif 21 in ports:
            app['protocol'] = 'FTP'
        elif 25 in ports or 587 in ports or 465 in ports:
            app['protocol'] = 'SMTP'
        elif 53 in ports:
            app['protocol'] = 'DNS'
        elif 3389 in ports:
            app['protocol'] = 'RDP'
        elif 445 in ports or 139 in ports:
            app['protocol'] = 'SMB'
        elif min_port in WELL_KNOWN_PORTS:
            app['protocol'] = WELL_KNOWN_PORTS[min_port]

        return app

    @staticmethod
    def _parse_dns(data):
        if len(data) < 12: return None
        try:
            txn_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', data[:12])
            qr = (flags >> 15) & 1
            opcode = (flags >> 11) & 0xF
            rcode = flags & 0xF

            queries = []
            offset = 12
            for _ in range(min(qdcount, 10)):
                name, offset = ProtocolDissector._parse_dns_name(data, offset)
                if offset + 4 <= len(data):
                    qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
                    offset += 4
                    queries.append({
                        'name': name,
                        'type': DNS_TYPES.get(qtype, f'TYPE-{qtype}'),
                        'type_num': qtype,
                        'class': qclass,
                    })

            answers = []
            for _ in range(min(ancount, 20)):
                if offset >= len(data): break
                name, offset = ProtocolDissector._parse_dns_name(data, offset)
                if offset + 10 > len(data): break
                rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', data[offset:offset + 10])
                offset += 10
                rdata = data[offset:offset + rdlen]
                offset += rdlen

                answer = {'name': name, 'type': DNS_TYPES.get(rtype, f'TYPE-{rtype}'),
                          'type_num': rtype, 'ttl': ttl, 'data': ''}
                if rtype == 1 and len(rdata) == 4:
                    answer['data'] = socket.inet_ntoa(rdata)
                elif rtype == 28 and len(rdata) == 16:
                    answer['data'] = socket.inet_ntop(socket.AF_INET6, rdata)
                elif rtype == 5:
                    answer['data'], _ = ProtocolDissector._parse_dns_name(data, offset - rdlen)
                elif rtype == 16:
                    answer['data'] = rdata[1:].decode('utf-8', errors='replace') if rdata else ''
                answers.append(answer)

            return {
                'protocol': 'DNS',
                'details': {
                    'transaction_id': txn_id,
                    'is_response': bool(qr),
                    'opcode': opcode,
                    'rcode': rcode,
                    'queries': queries,
                    'answers': answers,
                    'query_count': qdcount,
                    'answer_count': ancount,
                },
            }
        except:
            return None

    @staticmethod
    def _parse_dns_name(data, offset):
        labels = []
        seen = set()
        while offset < len(data):
            if offset in seen: break
            seen.add(offset)
            length = data[offset]
            if length == 0:
                offset += 1; break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data): break
                ptr = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3FFF
                name_part, _ = ProtocolDissector._parse_dns_name(data, ptr)
                labels.append(name_part)
                offset += 2; break
            else:
                offset += 1
                if offset + length > len(data): break
                labels.append(data[offset:offset + length].decode('utf-8', errors='replace'))
                offset += length
        return '.'.join(labels), offset

    @staticmethod
    def _parse_http_request(data):
        try:
            lines = data.split(b'\r\n')
            request_line = lines[0].decode('utf-8', errors='replace')
            parts = request_line.split(' ', 2)
            headers = {}
            for line in lines[1:]:
                if not line or line == b'': break
                decoded = line.decode('utf-8', errors='replace')
                if ':' in decoded:
                    k, _, v = decoded.partition(':')
                    headers[k.strip().lower()] = v.strip()

            return {
                'protocol': 'HTTP',
                'details': {
                    'method': parts[0] if parts else '',
                    'uri': parts[1] if len(parts) > 1 else '',
                    'version': parts[2] if len(parts) > 2 else '',
                    'host': headers.get('host', ''),
                    'user_agent': headers.get('user-agent', ''),
                    'content_type': headers.get('content-type', ''),
                    'content_length': headers.get('content-length', ''),
                    'referer': headers.get('referer', ''),
                    'cookie': '[present]' if 'cookie' in headers else '',
                    'authorization': '[present]' if 'authorization' in headers else '',
                    'headers': headers,
                    'is_request': True,
                },
            }
        except:
            return {'protocol': 'HTTP', 'details': {'is_request': True}}

    @staticmethod
    def _parse_http_response(data):
        try:
            lines = data.split(b'\r\n')
            status_line = lines[0].decode('utf-8', errors='replace')
            parts = status_line.split(' ', 2)
            headers = {}
            for line in lines[1:]:
                if not line: break
                decoded = line.decode('utf-8', errors='replace')
                if ':' in decoded:
                    k, _, v = decoded.partition(':')
                    headers[k.strip().lower()] = v.strip()
            return {
                'protocol': 'HTTP',
                'details': {
                    'version': parts[0] if parts else '',
                    'status_code': parts[1] if len(parts) > 1 else '',
                    'reason': parts[2] if len(parts) > 2 else '',
                    'server': headers.get('server', ''),
                    'content_type': headers.get('content-type', ''),
                    'headers': headers,
                    'is_request': False,
                },
            }
        except:
            return {'protocol': 'HTTP', 'details': {'is_request': False}}

    @staticmethod
    def _parse_tls(data):
        try:
            if len(data) < 5: return None
            content_type = data[0]
            if content_type != 0x16: return None  # Handshake
            version = struct.unpack('!H', data[1:3])[0]
            length = struct.unpack('!H', data[3:5])[0]

            result = {
                'protocol': 'TLS',
                'details': {
                    'record_version': TLS_VERSIONS.get(version, f'0x{version:04x}'),
                    'version': TLS_VERSIONS.get(version, f'0x{version:04x}'),
                    'version_num': version,
                    'content_type': 'Handshake',
                    'deprecated': version in DEPRECATED_TLS,
                    'sni': '',
                    'cipher_suites': [],
                },
            }

            if len(data) < 6: return result
            hs_type = data[5]

            # Client Hello
            if hs_type == 1 and len(data) > 43:
                # Read actual ClientHello version (bytes 9-10: after record hdr + hs type + length)
                if len(data) >= 11:
                    ch_version = struct.unpack('!H', data[9:11])[0]
                    result['details']['version'] = TLS_VERSIONS.get(ch_version, f'0x{ch_version:04x}')
                    result['details']['version_num'] = ch_version
                    result['details']['deprecated'] = ch_version in DEPRECATED_TLS

                # Skip to session ID
                off = 43
                if off < len(data):
                    sess_len = data[off]; off += 1 + sess_len
                if off + 2 <= len(data):
                    cs_len = struct.unpack('!H', data[off:off + 2])[0]; off += 2
                    cs_data = data[off:off + cs_len]
                    suites = []
                    for i in range(0, len(cs_data) - 1, 2):
                        suites.append(struct.unpack('!H', cs_data[i:i + 2])[0])
                    result['details']['cipher_suites'] = suites[:20]
                    off += cs_len

                # Skip compression
                if off < len(data):
                    comp_len = data[off]; off += 1 + comp_len

                # Extensions
                if off + 2 <= len(data):
                    ext_len = struct.unpack('!H', data[off:off + 2])[0]; off += 2
                    ext_end = off + ext_len
                    while off + 4 <= ext_end and off + 4 <= len(data):
                        ext_type = struct.unpack('!H', data[off:off + 2])[0]
                        ext_data_len = struct.unpack('!H', data[off + 2:off + 4])[0]
                        off += 4
                        if ext_type == 0 and ext_data_len > 5:  # SNI
                            sni_data = data[off:off + ext_data_len]
                            if len(sni_data) > 5:
                                name_len = struct.unpack('!H', sni_data[3:5])[0]
                                if len(sni_data) >= 5 + name_len:
                                    result['details']['sni'] = sni_data[5:5 + name_len].decode('utf-8', errors='replace')
                        off += ext_data_len

                result['details']['handshake'] = 'ClientHello'

            elif hs_type == 2:
                result['details']['handshake'] = 'ServerHello'

            return result
        except:
            return None

    @staticmethod
    def _build_summary(result):
        parts = []
        ip = result.get('ip')
        tr = result.get('transport')
        app = result.get('app')

        if ip:
            if ip.get('type') == 'arp':
                return f"ARP {ip.get('opcode_name','')} {ip.get('sender_ip','')} -> {ip.get('target_ip','')}"
            src = ip.get('src_ip', '?')
            dst = ip.get('dst_ip', '?')
            proto = ip.get('protocol_name', '')

            if tr:
                if tr.get('type') in ('tcp', 'udp'):
                    sp = tr.get('src_port', 0)
                    dp = tr.get('dst_port', 0)
                    flags = f" [{tr.get('flags_str', '')}]" if tr.get('type') == 'tcp' else ''
                    app_name = app.get('protocol', '') if app else ''
                    return f"{src}:{sp} -> {dst}:{dp} {proto}{flags} {app_name}".strip()
                elif tr.get('type') == 'icmp':
                    return f"{src} -> {dst} ICMP {tr.get('type_name', '')}"

            return f"{src} -> {dst} {proto}"

        return f"{'->'.join(result.get('layers', ['Unknown']))}"


# ═══════════════════════════════════════════════════════════════════════════════
# TRAFFIC ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
# TRAFFIC ANALYZER — NBAD ENGINE (50+ Detection Classes)
# ═══════════════════════════════════════════════════════════════════════════════

class TrafficAnalyzer:
    """Analyzes dissected packets for flows, statistics, and NBAD anomalies."""

    def __init__(self):
        self.flows = defaultdict(lambda: {
            'packets': 0, 'bytes': 0, 'start': float('inf'),
            'end': 0, 'flags_seen': set(), 'payload_bytes': 0,
            'syn_count': 0, 'rst_count': 0, 'fin_count': 0,
        })
        self.dns_queries = []
        self.dns_answers = []
        self.http_requests = []
        self.tls_handshakes = []
        self.arp_table = defaultdict(set)
        self.ip_counter = Counter()
        self.port_counter = Counter()
        self.protocol_counter = Counter()
        self.src_dst_pairs = Counter()
        self.packets_per_second = Counter()
        self.total_bytes = 0
        self.total_packets = 0
        self.unique_ips = set()
        self.unique_macs = set()
        self.external_ips = set()
        self.internal_ips = set()
        self.timestamps = []
        self.ttl_values = Counter()
        self.user_agents = Counter()
        self.anomalies = []
        self.iocs = []
        # For NBAD
        self.icmp_packets = []
        self.syn_packets = defaultdict(list)      # src -> [timestamps]
        self.udp_src_counter = Counter()          # src -> udp packet count
        self.icmp_src_counter = Counter()
        self.dns_domain_ips = defaultdict(set)    # domain -> set of IPs
        self.src_ports_scanned = defaultdict(set) # src -> ports contacted
        self.src_tcp_flags = defaultdict(Counter) # src -> flag_combo -> count
        self.http_src_count = Counter()
        self.auth_attempts = defaultdict(Counter) # (src,port) -> dst -> count
        self.all_packets = []                     # store for deep analysis

    def process(self, dissected_packets: List[Dict]) -> Dict:
        """Process all dissected packets and produce NBAD analysis."""
        self.all_packets = dissected_packets
        for pkt in dissected_packets:
            self._process_packet(pkt)

        # ── NBAD Detection Engine ──────────────────────────────────────────
        # RECONNAISSANCE (NBAD-01 to 10)
        self._detect_port_scan()
        self._detect_stealth_scan()
        self._detect_os_fingerprinting()
        self._detect_network_sweep()
        self._detect_service_probing()
        self._detect_snmp_enum()
        self._detect_smb_enum()
        self._detect_ldap_enum()
        self._detect_dns_zone_transfer()

        # C2 / BEACONING (NBAD-11 to 20)
        self._detect_beaconing()
        self._detect_irc_c2()
        self._detect_http_c2()
        self._detect_dns_c2()
        self._detect_icmp_c2()
        self._detect_dga()
        self._detect_fast_flux()
        self._detect_tor_usage()
        self._detect_c2_framework_ports()

        # MALWARE PORT INTELLIGENCE (NBAD-21+)
        self._detect_malware_ports()

        # DATA EXFILTRATION (NBAD-101 to 108)
        self._detect_data_exfil()
        self._detect_dns_tunneling()
        self._detect_icmp_tunneling()
        self._detect_http_exfil()
        self._detect_slow_drip_exfil()

        # DENIAL OF SERVICE (NBAD-109 to 116)
        self._detect_syn_flood()
        self._detect_udp_flood()
        self._detect_icmp_flood()
        self._detect_http_flood()
        self._detect_amplification_attacks()

        # LATERAL MOVEMENT (NBAD-117 to 124)
        self._detect_smb_lateral()
        self._detect_rdp_lateral()
        self._detect_ssh_lateral()
        self._detect_wmi_lateral()
        self._detect_psexec()
        self._detect_pass_the_hash()
        self._detect_kerberoasting()
        self._detect_winrm()

        # INJECTION / EXPLOITATION (NBAD-125 to 130)
        self._detect_sql_injection()
        self._detect_command_injection()
        self._detect_directory_traversal()
        self._detect_shellshock()
        self._detect_log4shell()

        # LAYER 2 ATTACKS (NBAD-131 to 134)
        self._detect_arp_spoofing()
        self._detect_arp_scan()
        self._detect_mac_flooding()

        # AUTHENTICATION ATTACKS (NBAD-135 to 140)
        self._detect_ssh_brute_force()
        self._detect_http_brute_force()
        self._detect_rdp_brute_force()
        self._detect_ftp_brute_force()
        self._detect_default_credentials()

        # CLEARTEXT PROTOCOLS (NBAD-141 to 146)
        self._detect_cleartext()

        # PROTOCOL ANOMALIES (NBAD-147 to 154)
        self._detect_tls_issues()
        self._detect_invalid_tcp_flags()
        self._detect_oversized_dns()
        self._detect_gre_tunneling()
        self._detect_socks_proxy()
        self._detect_http_connect_tunnel()

        # RANSOMWARE INDICATORS (NBAD-155 to 158)
        self._detect_ransomware()

        # THREAT ACTOR PATTERNS (NBAD-159 to 163)
        self._detect_threat_actor_ports()

        # RAT FAMILY DETECTION
        self._detect_rat_families()

        # ADVANCED EXPLOITATION (NBAD-170 to 176)
        self._detect_proxyshell()
        self._detect_spring4shell()
        self._detect_xxe_ssrf()
        self._detect_deserialization()

        # LAYER 2 ADVANCED (NBAD-177 to 181)
        self._detect_dhcp_starvation()
        self._detect_stp_manipulation()
        self._detect_vlan_hopping()

        # ADVANCED EXFILTRATION (NBAD-182 to 186)
        self._detect_smtp_exfil()
        self._detect_ftp_exfil()
        self._detect_cloud_exfil()

        # C2 ADVANCED (NBAD-187 to 190)
        self._detect_domain_fronting()
        self._detect_long_lived_sessions()
        self._detect_port_knocking()

        # CREDENTIAL ATTACKS ADVANCED (NBAD-191 to 194)
        self._detect_asrep_roasting()
        self._detect_ldap_brute_force()
        self._detect_smb_brute_force()
        self._detect_ntlm_relay()

        # MALWARE BEHAVIORAL (NBAD-195 to 199)
        self._detect_worm_propagation()
        self._detect_p2p_activity()
        self._detect_phishing_ports()
        self._detect_spyware_ports()
        self._detect_multi_stage_attack()
        self._run_nabd_docx_detections()

        return self._compile_results()

    # ──────────────────────────────────────────────────────────────────────────
    # PACKET PROCESSING
    # ──────────────────────────────────────────────────────────────────────────

    def _process_packet(self, pkt):
        self.total_packets += 1
        self.total_bytes += pkt.get('cap_len', 0)
        ts = pkt.get('timestamp', 0)
        if ts > 0:
            self.timestamps.append(ts)
            self.packets_per_second[int(ts)] += 1

        ip = pkt.get('ip')
        tr = pkt.get('transport')
        app = pkt.get('app')
        eth = pkt.get('ethernet')

        if eth:
            self.unique_macs.add(eth.get('src_mac', ''))
            self.unique_macs.add(eth.get('dst_mac', ''))

        if ip:
            if ip.get('type') == 'arp':
                self.protocol_counter['ARP'] += 1
                self.arp_table[ip.get('sender_ip', '')].add(ip.get('sender_mac', ''))
                return

            src_ip = ip.get('src_ip', '')
            dst_ip = ip.get('dst_ip', '')
            self.ip_counter[src_ip] += 1
            self.ip_counter[dst_ip] += 1
            self.unique_ips.add(src_ip)
            self.unique_ips.add(dst_ip)
            self.src_dst_pairs[(src_ip, dst_ip)] += 1

            for addr in [src_ip, dst_ip]:
                if _is_private(addr):
                    self.internal_ips.add(addr)
                else:
                    self.external_ips.add(addr)

            if ip.get('ttl'):
                self.ttl_values[ip['ttl']] += 1

            proto_name = ip.get('protocol_name', 'Other')
            self.protocol_counter[proto_name] += 1

            # ICMP tracking
            if ip.get('protocol') == 1 and tr:
                self.icmp_src_counter[src_ip] += 1
                self.icmp_packets.append({'src': src_ip, 'dst': dst_ip, 'ts': ts, 'tr': tr, 'len': pkt.get('cap_len', 0)})

        if tr:
            if tr.get('type') in ('tcp', 'udp'):
                sp = tr.get('src_port', 0)
                dp = tr.get('dst_port', 0)
                self.port_counter[sp] += 1
                self.port_counter[dp] += 1

                if ip:
                    src_ip = ip.get('src_ip', '')
                    # Track ports scanned by each source
                    self.src_ports_scanned[src_ip].add(dp)
                    # Track TCP flags per source
                    if tr.get('type') == 'tcp':
                        flags_str = tr.get('flags_str', '')
                        self.src_tcp_flags[src_ip][flags_str] += 1
                        if 'SYN' in tr.get('flag_names', []) and 'ACK' not in tr.get('flag_names', []):
                            self.syn_packets[src_ip].append(ts)

                # UDP flood tracking
                if tr.get('type') == 'udp' and ip:
                    self.udp_src_counter[ip.get('src_ip', '')] += 1

                # Auth attempt tracking
                if dp in (22, 80, 443, 3389, 21, 3306, 5432) and ip:
                    self.auth_attempts[(ip.get('src_ip',''), dp)][ip.get('dst_ip','')] += 1

                # Flow tracking
                flow_key = self._flow_key(ip, tr)
                flow = self.flows[flow_key]
                flow['packets'] += 1
                flow['bytes'] += pkt.get('cap_len', 0)
                flow['payload_bytes'] += tr.get('payload_len', 0)
                if ts > 0:
                    flow['start'] = min(flow['start'], ts)
                    flow['end'] = max(flow['end'], ts)
                if tr.get('type') == 'tcp':
                    flow['flags_seen'].update(tr.get('flag_names', []))
                    if 'SYN' in tr.get('flag_names', []):
                        flow['syn_count'] += 1
                    if 'RST' in tr.get('flag_names', []):
                        flow['rst_count'] += 1

        if app:
            proto = app.get('protocol', '')
            details = app.get('details', {})

            if proto == 'DNS':
                for q in details.get('queries', []):
                    self.dns_queries.append({
                        'name': q['name'], 'type': q['type'],
                        'timestamp': ts, 'src_ip': ip.get('src_ip', '') if ip else '',
                    })
                for a in details.get('answers', []):
                    self.dns_answers.append(a)
                    # Track domain->IPs for fast-flux
                    if isinstance(a, dict) and a.get('type') == 'A':
                        qnames = [q['name'] for q in details.get('queries', [])]
                        for qn in qnames:
                            self.dns_domain_ips[qn].add(a.get('data', ''))

            elif proto == 'HTTP':
                if details.get('is_request'):
                    src = ip.get('src_ip', '') if ip else ''
                    req = {
                        'method': details.get('method', ''),
                        'uri': details.get('uri', ''),
                        'host': details.get('host', ''),
                        'user_agent': details.get('user_agent', ''),
                        'timestamp': ts, 'src_ip': src,
                        'dst_ip': ip.get('dst_ip', '') if ip else '',
                    }
                    self.http_requests.append(req)
                    if details.get('user_agent'):
                        self.user_agents[details['user_agent']] += 1
                    self.http_src_count[src] += 1

            elif proto == 'TLS':
                self.tls_handshakes.append({
                    'sni': details.get('sni', ''),
                    'version': details.get('version', ''),
                    'version_num': details.get('version_num', 0),
                    'deprecated': details.get('deprecated', False),
                    'handshake': details.get('handshake', ''),
                    'timestamp': ts,
                    'src_ip': ip.get('src_ip', '') if ip else '',
                    'dst_ip': ip.get('dst_ip', '') if ip else '',
                })

    def _flow_key(self, ip, tr):
        if not ip or not tr: return ('unknown', 'unknown', 0, 0, '')
        src = ip.get('src_ip', ''); dst = ip.get('dst_ip', '')
        sp = tr.get('src_port', 0); dp = tr.get('dst_port', 0)
        proto = tr.get('type', '')
        if (src, sp) > (dst, dp):
            return (dst, src, dp, sp, proto)
        return (src, dst, sp, dp, proto)

    def _add_anomaly(self, severity, category, nbad_id, description, mitre=None, source=None, destination=None, extra=None):
        a = {
            'severity': severity,
            'category': category,
            'nbad_id': nbad_id,
            'description': description,
        }
        if mitre: a['mitre'] = mitre
        if source: a['source'] = source
        if destination: a['destination'] = destination
        if extra: a.update(extra)
        self.anomalies.append(a)

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-01 to 10: RECONNAISSANCE
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_port_scan(self):
        """NBAD-01: TCP/UDP Port Scan Detection. T1046"""
        for src, ports in self.src_ports_scanned.items():
            count = len(ports)
            if count > 20:
                severity = 'critical' if count > 100 else 'high'
                self._add_anomaly(severity, 'RECONNAISSANCE', 'NBAD-01',
                    f'Port scan from {src} — {count} unique ports probed',
                    mitre='T1046', source=src)
                self.iocs.append({'type': 'scanner_ip', 'value': src})

    def _detect_stealth_scan(self):
        """NBAD-02: Stealth Scan (FIN, NULL, XMAS). T1046"""
        fin_scanners = defaultdict(int)
        null_scanners = defaultdict(int)
        xmas_scanners = defaultdict(int)

        for src, flag_counts in self.src_tcp_flags.items():
            for flags_str, count in flag_counts.items():
                if flags_str == 'FIN' and not any(f in flags_str for f in ['SYN', 'ACK']):
                    fin_scanners[src] += count
                elif flags_str == '' or flags_str == 'None':
                    null_scanners[src] += count
                elif 'FIN' in flags_str and 'PSH' in flags_str and 'URG' in flags_str:
                    xmas_scanners[src] += count

        for src, count in fin_scanners.items():
            if count > 5:
                self._add_anomaly('high', 'RECONNAISSANCE', 'NBAD-02',
                    f'FIN stealth scan from {src} — {count} FIN-only packets (T1046)',
                    mitre='T1046', source=src)
        for src, count in null_scanners.items():
            if count > 5:
                self._add_anomaly('high', 'RECONNAISSANCE', 'NBAD-02',
                    f'NULL scan from {src} — {count} packets with no flags (T1046)',
                    mitre='T1046', source=src)
        for src, count in xmas_scanners.items():
            if count > 5:
                self._add_anomaly('high', 'RECONNAISSANCE', 'NBAD-02',
                    f'XMAS scan from {src} — {count} FIN+PSH+URG packets (T1046)',
                    mitre='T1046', source=src)

    def _detect_os_fingerprinting(self):
        """NBAD-03: OS Fingerprinting via TTL anomalies. T1592"""
        unusual_ttls = defaultdict(set)
        for pkt in self.all_packets:
            ip = pkt.get('ip')
            if ip and ip.get('type') == 'ipv4':
                ttl = ip.get('ttl', 64)
                # Unusual TTL values suggest crafted packets / OS fingerprinting
                if ttl not in (32, 64, 128, 255) and ttl > 0:
                    unusual_ttls[ip.get('src_ip','')].add(ttl)

        for src, ttls in unusual_ttls.items():
            if len(ttls) > 3:
                self._add_anomaly('medium', 'RECONNAISSANCE', 'NBAD-03',
                    f'OS fingerprinting suspected from {src} — {len(ttls)} unusual TTL values: {sorted(ttls)[:5]}',
                    mitre='T1592', source=src)

    def _detect_network_sweep(self):
        """NBAD-04: Network/Host Discovery Sweep. T1046"""
        # ICMP sweep: many different destinations from one source
        icmp_dst_per_src = defaultdict(set)
        for pkt_info in self.icmp_packets:
            icmp_dst_per_src[pkt_info['src']].add(pkt_info['dst'])

        for src, dsts in icmp_dst_per_src.items():
            if len(dsts) > 15:
                self._add_anomaly('high', 'RECONNAISSANCE', 'NBAD-04',
                    f'ICMP network sweep from {src} — pinged {len(dsts)} hosts',
                    mitre='T1046', source=src)

        # TCP SYN sweep on same port to many hosts
        syn_dst_per_src = defaultdict(lambda: defaultdict(set))
        for fk, fv in self.flows.items():
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if proto == 'tcp' and fv['syn_count'] > 0 and fv['rst_count'] > 0:
                    syn_dst_per_src[src][dp].add(dst)

        for src, port_dsts in syn_dst_per_src.items():
            for port, dsts in port_dsts.items():
                if len(dsts) > 10:
                    self._add_anomaly('high', 'RECONNAISSANCE', 'NBAD-04',
                        f'TCP SYN sweep from {src} on port {port} to {len(dsts)} hosts',
                        mitre='T1046', source=src)

    def _detect_service_probing(self):
        """NBAD-05: Service Version Probing. T1046"""
        common_svc_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 5900}
        probed = defaultdict(set)
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp in common_svc_ports:
                    probed[src].add(dp)

        for src, ports in probed.items():
            if len(ports) >= 6:
                self._add_anomaly('medium', 'RECONNAISSANCE', 'NBAD-05',
                    f'Service probing from {src} — checked {len(ports)} service ports: {sorted(ports)[:8]}',
                    mitre='T1046', source=src)

    def _detect_snmp_enum(self):
        """NBAD-06: SNMP Enumeration. T1046"""
        snmp_src = defaultdict(set)
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp in (161, 162) and proto == 'udp':
                    snmp_src[src].add(dst)

        for src, dsts in snmp_src.items():
            if len(dsts) > 3:
                self._add_anomaly('medium', 'RECONNAISSANCE', 'NBAD-06',
                    f'SNMP enumeration from {src} — queried {len(dsts)} hosts on UDP/161-162',
                    mitre='T1046', source=src)

    def _detect_smb_enum(self):
        """NBAD-07: SMB/NetBIOS Enumeration. T1135"""
        smb_src = defaultdict(set)
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp in (445, 139, 137, 138):
                    smb_src[src].add(dst)

        for src, dsts in smb_src.items():
            if len(dsts) > 5:
                self._add_anomaly('high', 'RECONNAISSANCE', 'NBAD-07',
                    f'SMB/NetBIOS enumeration from {src} — scanned {len(dsts)} hosts',
                    mitre='T1135', source=src)

    def _detect_ldap_enum(self):
        """NBAD-08: LDAP Enumeration. T1087"""
        ldap_src = defaultdict(set)
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp in (389, 636, 3268, 3269):
                    ldap_src[src].add(dst)

        for src, dsts in ldap_src.items():
            if len(dsts) > 3:
                self._add_anomaly('medium', 'RECONNAISSANCE', 'NBAD-08',
                    f'LDAP enumeration from {src} — queried {len(dsts)} hosts on LDAP/LDAPS',
                    mitre='T1087', source=src)

    def _detect_dns_zone_transfer(self):
        """NBAD-09: DNS Zone Transfer Attempt. T1590"""
        for q in self.dns_queries:
            if q.get('type') in ('AXFR', 'IXFR'):
                self._add_anomaly('high', 'RECONNAISSANCE', 'NBAD-09',
                    f'DNS zone transfer ({q["type"]}) attempted for {q["name"]} from {q.get("src_ip","")}',
                    mitre='T1590')
                self.iocs.append({'type': 'dns_zone_transfer', 'value': q['name']})

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-11 to 20: C2 / BEACONING
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_beaconing(self):
        """NBAD-11: C2 Beaconing (periodic connections). T1071"""
        seen_pairs = set()
        for fk in self.flows:
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            pair = (src, dst)
            if pair in seen_pairs: continue

            # Collect all flow timestamps for this src->dst pair
            pair_times = []
            for fk2, fv2 in self.flows.items():
                if len(fk2) == 5:
                    s2, d2 = fk2[0], fk2[1]
                    if (s2 == src and d2 == dst) or (s2 == dst and d2 == src):
                        if fv2['start'] < float('inf'):
                            pair_times.append(fv2['start'])

            if len(pair_times) < 4: continue
            seen_pairs.add(pair)
            pair_times.sort()
            intervals = [pair_times[i+1] - pair_times[i] for i in range(len(pair_times)-1)]
            if not intervals: continue
            mean_int = sum(intervals) / len(intervals)
            if mean_int < 1: continue
            variance = sum((i - mean_int)**2 for i in intervals) / len(intervals)
            std_dev = math.sqrt(variance) if variance > 0 else 0
            cv = std_dev / mean_int if mean_int > 0 else float('inf')

            if cv < 0.20 and 5 < mean_int < 86400:
                count = self.src_dst_pairs.get((src, dst), 0) + self.src_dst_pairs.get((dst, src), 0)
                self._add_anomaly('critical', 'C2_BEACONING', 'NBAD-11',
                    f'C2 beaconing: {src} → {dst} every ~{mean_int:.0f}s (CV={cv:.3f}, {len(pair_times)} flows)',
                    mitre='T1071', source=src, destination=dst)
                self.iocs.append({'type': 'c2_beacon', 'value': f'{src} → {dst} @{mean_int:.0f}s'})

    def _detect_irc_c2(self):
        """NBAD-12: IRC-based C2 Communication. T1071.003"""
        irc_ports = {6667, 6668, 6669, 6697, 7000, 7001, 1080}
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp in irc_ports and not _is_private(dst):
                    self._add_anomaly('high', 'C2_BEACONING', 'NBAD-12',
                        f'IRC C2 channel suspected: {src} → {dst}:{dp} (external IRC)',
                        mitre='T1071.003', source=src, destination=dst)
                    self.iocs.append({'type': 'irc_c2', 'value': f'{dst}:{dp}'})

    def _detect_http_c2(self):
        """NBAD-13: HTTP/HTTPS C2 Communication. T1071.001"""
        suspicious_ua_patterns = [
            'Go-http-client', 'python-requests', 'curl/', 'libwww-perl',
            'Wget/', 'axios/', 'okhttp', 'Java/', 'Ruby',
        ]
        for req in self.http_requests:
            ua = req.get('user_agent', '')
            if any(p.lower() in ua.lower() for p in suspicious_ua_patterns):
                if not _is_private(req.get('dst_ip', '127.0.0.1')):
                    self._add_anomaly('medium', 'C2_BEACONING', 'NBAD-13',
                        f'Suspicious HTTP C2 user-agent: "{ua[:60]}" → {req.get("host","")}',
                        mitre='T1071.001', source=req.get('src_ip',''))
                    self.iocs.append({'type': 'suspicious_ua', 'value': ua[:80]})

        # Regular intervals to non-standard HTTP ports
        nonstandard_http = {8080, 8081, 8082, 8088, 8880, 8000, 8001, 8008, 9000, 9080}
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp in nonstandard_http and not _is_private(dst) and proto == 'tcp':
                    self._add_anomaly('medium', 'C2_BEACONING', 'NBAD-13',
                        f'HTTP C2 on non-standard port: {src} → {dst}:{dp}',
                        mitre='T1071.001', source=src, destination=dst)

    def _detect_dns_c2(self):
        """NBAD-14: DNS-based C2. T1071.004"""
        domain_counts = defaultdict(list)
        for q in self.dns_queries:
            name = q.get('name', '')
            parts = name.split('.')
            if len(parts) > 2:
                base = '.'.join(parts[-2:])
                subdomain = '.'.join(parts[:-2])
                domain_counts[base].append({'sub': subdomain, 'full': name, 'src': q.get('src_ip', ''), 'ts': q.get('timestamp', 0)})

        for base, entries in domain_counts.items():
            if len(entries) >= 8:
                avg_len = sum(len(e['sub']) for e in entries) / len(entries)
                # High entropy subdomains = encoded C2 data
                avg_entropy = sum(_entropy(e['sub']) for e in entries) / len(entries)
                if avg_entropy > 3.5 or avg_len > 25:
                    self._add_anomaly('critical', 'C2_BEACONING', 'NBAD-14',
                        f'DNS C2/tunneling: {base} — {len(entries)} queries, avg entropy={avg_entropy:.2f}, avg subdomain len={avg_len:.0f}',
                        mitre='T1071.004')
                    self.iocs.append({'type': 'dns_c2_domain', 'value': base})

        # High volume DNS to single domain
        domain_freq = Counter(q.get('name', '').split('.')[-2] + '.' + q.get('name', '').split('.')[-1]
                               for q in self.dns_queries if len(q.get('name', '').split('.')) >= 2)
        for domain, count in domain_freq.most_common(5):
            if count > 50:
                self._add_anomaly('medium', 'C2_BEACONING', 'NBAD-14',
                    f'Excessive DNS queries to {domain}: {count} queries (possible C2 polling)',
                    mitre='T1071.004')

    def _detect_icmp_c2(self):
        """NBAD-15: ICMP-based C2 / Covert Channel. T1095"""
        # Large ICMP payloads suggest covert channel
        for pkt_info in self.icmp_packets:
            if pkt_info['len'] > 200:
                self._add_anomaly('high', 'C2_BEACONING', 'NBAD-15',
                    f'Large ICMP packet ({pkt_info["len"]} bytes) from {pkt_info["src"]} — possible ICMP C2/covert channel',
                    mitre='T1095', source=pkt_info['src'])

        # Many ICMP echo requests to external host
        icmp_ext = defaultdict(int)
        for pkt_info in self.icmp_packets:
            if not _is_private(pkt_info['dst']):
                icmp_ext[pkt_info['src']] += 1
        for src, count in icmp_ext.items():
            if count > 20:
                self._add_anomaly('medium', 'C2_BEACONING', 'NBAD-15',
                    f'ICMP C2 suspected: {src} sent {count} ICMP packets to external hosts',
                    mitre='T1095', source=src)

    def _detect_dga(self):
        """NBAD-16: Domain Generation Algorithm (DGA). T1568.002"""
        for q in self.dns_queries:
            name = q.get('name', '')
            parts = name.split('.')
            if len(parts) >= 2:
                label = parts[0]
                ent = _entropy(label)
                # DGA: high entropy + long + no vowels pattern
                vowels = sum(1 for c in label.lower() if c in 'aeiou')
                vowel_ratio = vowels / len(label) if label else 0
                if ent > 3.5 and len(label) > 10 and vowel_ratio < 0.20:
                    self._add_anomaly('high', 'C2_BEACONING', 'NBAD-16',
                        f'DGA domain suspected: {name} (entropy={ent:.2f}, len={len(label)}, vowels={vowel_ratio:.1%})',
                        mitre='T1568.002', source=q.get('src_ip',''))
                    self.iocs.append({'type': 'dga_domain', 'value': name})

    def _detect_fast_flux(self):
        """NBAD-17: Fast-Flux DNS. T1568.001"""
        for domain, ips in self.dns_domain_ips.items():
            if len(ips) > 4:
                self._add_anomaly('high', 'C2_BEACONING', 'NBAD-17',
                    f'Fast-flux DNS: {domain} resolved to {len(ips)} IPs: {list(ips)[:5]}',
                    mitre='T1568.001')
                self.iocs.append({'type': 'fast_flux_domain', 'value': domain})

    def _detect_tor_usage(self):
        """NBAD-18: Tor Network Usage. T1090.003"""
        tor_ports = {9001, 9050, 9051, 9150, 9151, 9030}
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp in tor_ports or sp in tor_ports:
                    self._add_anomaly('high', 'C2_BEACONING', 'NBAD-18',
                        f'Tor network usage detected: {src} ↔ {dst}:{dp}',
                        mitre='T1090.003', source=src)
                    self.iocs.append({'type': 'tor_usage', 'value': f'{src}:{dp}'})

    def _detect_c2_framework_ports(self):
        """NBAD-19: C2 Framework Port Detection (Cobalt Strike, Sliver, Metasploit). T1219"""
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            port = dp
            if port in MALICIOUS_PORTS_DB:
                db = MALICIOUS_PORTS_DB[port]
                types_set = set(db['types'])
                names = db['names']
                names_lower = ' '.join(names).lower()
                c2_kws = ['cobalt', 'metasploit', 'empire', 'sliver', 'meterpreter',
                          'havoc', 'brute ratel', 'xworm', 'asyncrat', 'quasar', 'njrat', 'remcos']
                if any(k in names_lower for k in c2_kws):
                    severity = 'critical' if types_set & HIGH_SEVERITY_TYPES else 'high'
                    self._add_anomaly(severity, 'C2_BEACONING', 'NBAD-19',
                        f'C2 framework port {port} ({", ".join(names[:2])}): {src} → {dst}',
                        mitre='T1219', source=src, destination=dst)
                    self.iocs.append({'type': 'c2_framework_port', 'value': f'{dst}:{port}'})

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-21+: MALWARE PORT INTELLIGENCE (566 ports)
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_malware_ports(self):
        """NBAD-21: HFL Threat Intel Port Detection. T1571"""
        alerted = set()
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            for port in (sp, dp):
                key = (src if port == dp else dst, port)
                if key in alerted: continue
                if port in MALICIOUS_PORTS_DB:
                    db = MALICIOUS_PORTS_DB[port]
                    types_set = set(db['types'])
                    names = db['names']
                    adv_type = ', '.join(db['types'])
                    adv_names = ', '.join(names[:3]) + ('...' if len(names) > 3 else '')

                    if types_set & HIGH_SEVERITY_TYPES:
                        severity = 'critical'
                    elif types_set & MEDIUM_SEVERITY_TYPES:
                        severity = 'high'
                    else:
                        severity = 'medium'

                    direction = f'{src} → {dst}' if port == dp else f'{dst} → {src}'
                    self._add_anomaly(severity, 'MALWARE_PORT', 'NBAD-21',
                        f'Malicious port {port}/{proto.upper()} [{adv_type}] — {adv_names} | {direction}',
                        mitre='T1571', source=src, destination=dst)
                    self.iocs.append({'type': 'malicious_port', 'value': f'port/{port}/{adv_type}'})
                    alerted.add(key)

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-101 to 108: DATA EXFILTRATION
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_data_exfil(self):
        """NBAD-101: Large Data Exfiltration. T1041"""
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if fv['payload_bytes'] > 10 * 1024 * 1024 and not _is_private(dst):
                self._add_anomaly('critical', 'EXFILTRATION', 'NBAD-101',
                    f'Large outbound transfer: {src} → {dst} ({_human_bytes(fv["payload_bytes"])})',
                    mitre='T1041', source=src, destination=dst)
                self.iocs.append({'type': 'exfil_dst', 'value': dst})
            elif fv['payload_bytes'] > 1 * 1024 * 1024 and not _is_private(dst):
                duration = fv['end'] - fv['start']
                if duration > 0:
                    rate = fv['payload_bytes'] / duration
                    if rate > 5 * 1024 * 1024:
                        self._add_anomaly('high', 'EXFILTRATION', 'NBAD-101',
                            f'High-rate outbound: {src} → {dst} @ {_human_bytes(rate)}/s',
                            mitre='T1041', source=src, destination=dst)

    def _detect_dns_tunneling(self):
        """NBAD-102: DNS Tunneling. T1048.003"""
        domain_counts = defaultdict(list)
        for q in self.dns_queries:
            name = q.get('name', '')
            parts = name.split('.')
            if len(parts) > 2:
                subdomain = '.'.join(parts[:-2])
                base_domain = '.'.join(parts[-2:])
                domain_counts[base_domain].append(len(subdomain))

        for domain, lengths in domain_counts.items():
            if len(lengths) < 5: continue
            avg_len = sum(lengths) / len(lengths)
            if avg_len > 30 and len(lengths) > 10:
                self._add_anomaly('critical', 'EXFILTRATION', 'NBAD-102',
                    f'DNS tunneling: {domain} — {len(lengths)} queries, avg subdomain {avg_len:.0f} chars',
                    mitre='T1048.003')
                self.iocs.append({'type': 'dns_tunnel_domain', 'value': domain})

    def _detect_icmp_tunneling(self):
        """NBAD-103: ICMP Tunneling / Covert Channel. T1095"""
        # Track ICMP size anomalies
        icmp_large_src = defaultdict(int)
        for pkt_info in self.icmp_packets:
            if pkt_info['len'] > 100:
                icmp_large_src[pkt_info['src']] += 1

        for src, count in icmp_large_src.items():
            if count > 5:
                self._add_anomaly('high', 'EXFILTRATION', 'NBAD-103',
                    f'ICMP tunneling suspected: {src} sent {count} large ICMP packets (>100 bytes)',
                    mitre='T1095', source=src)

    def _detect_http_exfil(self):
        """NBAD-104: HTTP POST Exfiltration. T1048.002"""
        post_by_src = defaultdict(lambda: {'count': 0, 'hosts': set()})
        for req in self.http_requests:
            if req.get('method') == 'POST':
                src = req.get('src_ip', '')
                host = req.get('host', '')
                if not _is_private(req.get('dst_ip', '127.0.0.1')):
                    post_by_src[src]['count'] += 1
                    post_by_src[src]['hosts'].add(host)

        for src, data in post_by_src.items():
            if data['count'] > 5:
                self._add_anomaly('high', 'EXFILTRATION', 'NBAD-104',
                    f'HTTP POST exfiltration: {src} — {data["count"]} POSTs to external hosts: {list(data["hosts"])[:3]}',
                    mitre='T1048.002', source=src)

    def _detect_slow_drip_exfil(self):
        """NBAD-105: Slow Drip / Low-and-Slow Exfiltration. T1048"""
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            duration = fv['end'] - fv['start']
            if duration > 60 and not _is_private(dst):
                rate = fv['payload_bytes'] / duration if duration > 0 else 0
                # Very slow sustained transfer 1KB-50KB total
                if 1024 < fv['payload_bytes'] < 51200 and duration > 300 and rate < 200:
                    self._add_anomaly('medium', 'EXFILTRATION', 'NBAD-105',
                        f'Slow-drip exfil: {src} → {dst} — {_human_bytes(fv["payload_bytes"])} over {duration:.0f}s ({rate:.0f} B/s)',
                        mitre='T1048', source=src, destination=dst)

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-109 to 116: DENIAL OF SERVICE
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_syn_flood(self):
        """NBAD-109: SYN Flood / TCP DoS. T1498.001"""
        for src, timestamps in self.syn_packets.items():
            if len(timestamps) > 50:
                duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 1
                rate = len(timestamps) / max(duration, 1)
                if rate > 10:  # >10 SYNs/sec
                    self._add_anomaly('critical', 'DENIAL_OF_SERVICE', 'NBAD-109',
                        f'SYN flood from {src}: {len(timestamps)} SYN packets, {rate:.0f}/s over {duration:.0f}s',
                        mitre='T1498.001', source=src)

    def _detect_udp_flood(self):
        """NBAD-110: UDP Flood. T1498"""
        for src, count in self.udp_src_counter.items():
            if count > 500:
                self._add_anomaly('critical', 'DENIAL_OF_SERVICE', 'NBAD-110',
                    f'UDP flood from {src}: {count} UDP packets',
                    mitre='T1498', source=src)

    def _detect_icmp_flood(self):
        """NBAD-111: ICMP Flood / Smurf Attack. T1498"""
        for src, count in self.icmp_src_counter.items():
            if count > 200:
                self._add_anomaly('high', 'DENIAL_OF_SERVICE', 'NBAD-111',
                    f'ICMP flood from {src}: {count} ICMP packets',
                    mitre='T1498', source=src)

    def _detect_http_flood(self):
        """NBAD-112: HTTP Flood. T1499"""
        for src, count in self.http_src_count.items():
            if count > 100:
                self._add_anomaly('high', 'DENIAL_OF_SERVICE', 'NBAD-112',
                    f'HTTP flood from {src}: {count} HTTP requests',
                    mitre='T1499', source=src)

    def _detect_amplification_attacks(self):
        """NBAD-113: Amplification Attacks (DNS/NTP/SSDP). T1498.002"""
        dns_src = Counter()
        ntp_src = Counter()
        ssdp_src = Counter()

        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp == 53 and proto == 'udp': dns_src[src] += 1
                if dp == 123 and proto == 'udp': ntp_src[src] += 1
                if dp == 1900 and proto == 'udp': ssdp_src[src] += 1

        for src, count in dns_src.items():
            if count > 30:
                self._add_anomaly('high', 'DENIAL_OF_SERVICE', 'NBAD-113',
                    f'DNS amplification attack from {src}: {count} DNS queries',
                    mitre='T1498.002', source=src)
        for src, count in ntp_src.items():
            if count > 20:
                self._add_anomaly('high', 'DENIAL_OF_SERVICE', 'NBAD-113',
                    f'NTP amplification attack from {src}: {count} NTP requests',
                    mitre='T1498.002', source=src)
        for src, count in ssdp_src.items():
            if count > 10:
                self._add_anomaly('medium', 'DENIAL_OF_SERVICE', 'NBAD-113',
                    f'SSDP amplification from {src}: {count} SSDP requests',
                    mitre='T1498.002', source=src)

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-117 to 124: LATERAL MOVEMENT
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_smb_lateral(self):
        """NBAD-117: SMB Lateral Movement. T1021.002"""
        smb_conns = defaultdict(set)
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp == 445 and _is_private(dst):
                    smb_conns[src].add(dst)

        for src, dsts in smb_conns.items():
            if len(dsts) > 3:
                self._add_anomaly('high', 'LATERAL_MOVEMENT', 'NBAD-117',
                    f'SMB lateral movement: {src} connected to {len(dsts)} internal hosts via SMB/445',
                    mitre='T1021.002', source=src)

    def _detect_rdp_lateral(self):
        """NBAD-118: RDP Lateral Movement. T1021.001"""
        rdp_src = defaultdict(set)
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp == 3389 and _is_private(dst):
                    rdp_src[src].add(dst)

        for src, dsts in rdp_src.items():
            if len(dsts) > 2:
                self._add_anomaly('high', 'LATERAL_MOVEMENT', 'NBAD-118',
                    f'RDP lateral movement: {src} connected to {len(dsts)} internal hosts via RDP/3389',
                    mitre='T1021.001', source=src)

    def _detect_ssh_lateral(self):
        """NBAD-119: SSH Lateral Movement. T1021.004"""
        ssh_src = defaultdict(set)
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp == 22 and _is_private(dst):
                    ssh_src[src].add(dst)

        for src, dsts in ssh_src.items():
            if len(dsts) > 3:
                self._add_anomaly('medium', 'LATERAL_MOVEMENT', 'NBAD-119',
                    f'SSH lateral movement: {src} connected to {len(dsts)} internal hosts via SSH/22',
                    mitre='T1021.004', source=src)

    def _detect_wmi_lateral(self):
        """NBAD-120: WMI/DCOM Lateral Movement. T1021.003"""
        wmi_src = defaultdict(set)
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp in (135, 445) and _is_private(dst):
                    wmi_src[src].add(dst)

        for src, dsts in wmi_src.items():
            if len(dsts) > 4:
                self._add_anomaly('high', 'LATERAL_MOVEMENT', 'NBAD-120',
                    f'WMI/DCOM lateral movement: {src} — RPC/SMB to {len(dsts)} internal hosts',
                    mitre='T1021.003', source=src)

    def _detect_psexec(self):
        """NBAD-121: PsExec-style Remote Execution. T1570"""
        # PsExec pattern: SMB + high port back-channel
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp == 445 and proto == 'tcp' and _is_private(dst):
                    # Check if there's also high-port traffic (ADMIN$ share)
                    for fk2 in self.flows:
                        if len(fk2) == 5:
                            s2, d2, sp2, dp2, p2 = fk2
                            if s2 == src and d2 == dst and dp2 > 49000:
                                self._add_anomaly('critical', 'LATERAL_MOVEMENT', 'NBAD-121',
                                    f'PsExec/remote execution: {src} → {dst} (SMB+high-port pattern)',
                                    mitre='T1570', source=src, destination=dst)
                                break

    def _detect_pass_the_hash(self):
        """NBAD-122: Pass-the-Hash / NTLM Authentication Attack. T1550.002"""
        # Detect multiple rapid SMB authentications
        smb_auth = defaultdict(list)
        for pkt in self.all_packets:
            ip = pkt.get('ip')
            tr = pkt.get('transport')
            if ip and tr and tr.get('type') == 'tcp' and tr.get('dst_port') == 445:
                smb_auth[ip.get('src_ip','')].append(pkt.get('timestamp', 0))

        for src, times in smb_auth.items():
            if len(times) > 10:
                duration = max(times) - min(times) if len(times) > 1 else 1
                if duration < 30:  # Many SMB auths in <30s
                    self._add_anomaly('critical', 'LATERAL_MOVEMENT', 'NBAD-122',
                        f'Pass-the-Hash suspected: {src} — {len(times)} SMB auth attempts in {duration:.0f}s',
                        mitre='T1550.002', source=src)

    def _detect_kerberoasting(self):
        """NBAD-123: Kerberoasting / Kerberos Attack. T1558.003"""
        kerb_src = defaultdict(set)
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp == 88:  # Kerberos
                    kerb_src[src].add(dst)

        for src, dsts in kerb_src.items():
            if len(dsts) > 3:
                self._add_anomaly('high', 'LATERAL_MOVEMENT', 'NBAD-123',
                    f'Kerberoasting suspected: {src} — {len(dsts)} Kerberos service ticket requests',
                    mitre='T1558.003', source=src)

    def _detect_winrm(self):
        """NBAD-124: WinRM Abuse. T1021.006"""
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp in (5985, 5986, 47001) and _is_private(dst):
                    self._add_anomaly('medium', 'LATERAL_MOVEMENT', 'NBAD-124',
                        f'WinRM lateral movement: {src} → {dst}:{dp}',
                        mitre='T1021.006', source=src, destination=dst)

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-125 to 130: INJECTION / EXPLOITATION
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_sql_injection(self):
        """NBAD-125: SQL Injection Attempts. T1190"""
        sqli_patterns = ["' or ", "' and ", "union select", "' --", "/**/",
                         "1=1", "xp_cmdshell", "information_schema", "sleep(", "waitfor delay"]
        for req in self.http_requests:
            uri = (req.get('uri', '') + req.get('host', '')).lower()
            if any(p in uri for p in sqli_patterns):
                self._add_anomaly('critical', 'EXPLOITATION', 'NBAD-125',
                    f'SQL injection attempt: {req.get("src_ip","")} → {req.get("host","")}{req.get("uri","")[:60]}',
                    mitre='T1190', source=req.get('src_ip',''))
                self.iocs.append({'type': 'sqli_attempt', 'value': req.get('host','')})

    def _detect_command_injection(self):
        """NBAD-126: Command Injection Attempts. T1190"""
        cmdi_patterns = [';ls', ';id', ';cat', '|whoami', '`id`', '$(id)', ';wget', ';curl',
                         ';nc ', ';bash', ';/bin/sh', '&&whoami', '||id']
        for req in self.http_requests:
            uri = req.get('uri', '').lower()
            if any(p in uri for p in cmdi_patterns):
                self._add_anomaly('critical', 'EXPLOITATION', 'NBAD-126',
                    f'Command injection attempt: {req.get("src_ip","")} → {req.get("host","")}{req.get("uri","")[:60]}',
                    mitre='T1190', source=req.get('src_ip',''))

    def _detect_directory_traversal(self):
        """NBAD-127: Directory Traversal. T1083"""
        traversal = ['../../../', '..\\..\\', '%2e%2e%2f', '%252e%252e', 'etc/passwd', 'etc/shadow',
                     'windows/system32', '/proc/self']
        for req in self.http_requests:
            uri = req.get('uri', '').lower()
            if any(p in uri for p in traversal):
                self._add_anomaly('critical', 'EXPLOITATION', 'NBAD-127',
                    f'Directory traversal: {req.get("src_ip","")} → {req.get("host","")}{req.get("uri","")[:60]}',
                    mitre='T1083', source=req.get('src_ip',''))

    def _detect_shellshock(self):
        """NBAD-128: Shellshock (CVE-2014-6271) Exploitation. T1190"""
        for req in self.http_requests:
            ua = req.get('user_agent', '')
            host = req.get('host', '')
            if '() {' in ua or '() {' in host:
                self._add_anomaly('critical', 'EXPLOITATION', 'NBAD-128',
                    f'Shellshock (CVE-2014-6271) attempt from {req.get("src_ip","")}: {ua[:60]}',
                    mitre='T1190', source=req.get('src_ip',''))

    def _detect_log4shell(self):
        """NBAD-129: Log4Shell (CVE-2021-44228) Exploitation. T1190"""
        for req in self.http_requests:
            for field in [req.get('uri',''), req.get('user_agent',''), req.get('host','')]:
                if '${jndi:' in field.lower():
                    self._add_anomaly('critical', 'EXPLOITATION', 'NBAD-129',
                        f'Log4Shell (CVE-2021-44228) attempt from {req.get("src_ip","")}: {field[:80]}',
                        mitre='T1190', source=req.get('src_ip',''))
                    self.iocs.append({'type': 'log4shell', 'value': req.get('src_ip','')})
                    break

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-131 to 134: LAYER 2 ATTACKS
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_arp_spoofing(self):
        """NBAD-131: ARP Spoofing / Cache Poisoning. T1557.002"""
        for ip_addr, macs in self.arp_table.items():
            macs_clean = {m for m in macs if m != '00:00:00:00:00:00'}
            if len(macs_clean) > 1:
                self._add_anomaly('critical', 'LAYER2_ATTACK', 'NBAD-131',
                    f'ARP spoofing: IP {ip_addr} has {len(macs_clean)} MACs: {", ".join(macs_clean)}',
                    mitre='T1557.002')
                self.iocs.append({'type': 'arp_spoof_ip', 'value': ip_addr})

    def _detect_arp_scan(self):
        """NBAD-132: ARP Network Scan. T1046"""
        arp_src = defaultdict(set)
        for pkt in self.all_packets:
            ip = pkt.get('ip')
            if ip and ip.get('type') == 'arp' and ip.get('opcode') == 1:
                arp_src[ip.get('sender_ip','')].add(ip.get('target_ip',''))

        for src, targets in arp_src.items():
            if len(targets) > 15:
                self._add_anomaly('medium', 'LAYER2_ATTACK', 'NBAD-132',
                    f'ARP scan from {src}: probed {len(targets)} IP addresses',
                    mitre='T1046', source=src)

    def _detect_mac_flooding(self):
        """NBAD-133: MAC Flooding (CAM Table Overflow). T1557"""
        if len(self.unique_macs) > 200:
            self._add_anomaly('high', 'LAYER2_ATTACK', 'NBAD-133',
                f'MAC flooding suspected: {len(self.unique_macs)} unique MAC addresses observed',
                mitre='T1557')

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-135 to 140: AUTHENTICATION ATTACKS
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_ssh_brute_force(self):
        """NBAD-135: SSH Brute Force. T1110.001"""
        for (src, port), dst_counts in self.auth_attempts.items():
            if port == 22:
                total = sum(dst_counts.values())
                if total > 10:
                    self._add_anomaly('high', 'AUTH_ATTACK', 'NBAD-135',
                        f'SSH brute force: {src} — {total} SSH connection attempts',
                        mitre='T1110.001', source=src)
                    self.iocs.append({'type': 'brute_force_src', 'value': f'{src}:SSH'})

    def _detect_http_brute_force(self):
        """NBAD-136: HTTP Auth Brute Force. T1110.001"""
        for (src, port), dst_counts in self.auth_attempts.items():
            if port in (80, 443):
                total = sum(dst_counts.values())
                if total > 20:
                    self._add_anomaly('high', 'AUTH_ATTACK', 'NBAD-136',
                        f'HTTP brute force: {src} — {total} HTTP auth attempts',
                        mitre='T1110.001', source=src)

    def _detect_rdp_brute_force(self):
        """NBAD-137: RDP Brute Force. T1110.001"""
        for (src, port), dst_counts in self.auth_attempts.items():
            if port == 3389:
                total = sum(dst_counts.values())
                if total > 5:
                    self._add_anomaly('high', 'AUTH_ATTACK', 'NBAD-137',
                        f'RDP brute force: {src} — {total} RDP connection attempts',
                        mitre='T1110.001', source=src)
                    self.iocs.append({'type': 'brute_force_src', 'value': f'{src}:RDP'})

    def _detect_ftp_brute_force(self):
        """NBAD-138: FTP Brute Force. T1110.001"""
        for (src, port), dst_counts in self.auth_attempts.items():
            if port == 21:
                total = sum(dst_counts.values())
                if total > 10:
                    self._add_anomaly('medium', 'AUTH_ATTACK', 'NBAD-138',
                        f'FTP brute force: {src} — {total} FTP connection attempts',
                        mitre='T1110.001', source=src)

    def _detect_default_credentials(self):
        """NBAD-139: Default Credential Usage. T1078.001"""
        # Telnet to many hosts = possible default creds
        telnet_src = defaultdict(set)
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp == 23:
                    telnet_src[src].add(dst)

        for src, dsts in telnet_src.items():
            if len(dsts) > 3:
                self._add_anomaly('high', 'AUTH_ATTACK', 'NBAD-139',
                    f'Default credential spray: {src} — Telnet to {len(dsts)} hosts',
                    mitre='T1078.001', source=src)

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-141 to 146: CLEARTEXT PROTOCOLS
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_cleartext(self):
        """NBAD-141 to 146: Cleartext Protocol Detection. T1040"""
        # HTTP POST (cleartext)
        for req in self.http_requests:
            if req.get('method') == 'POST':
                self._add_anomaly('medium', 'CLEARTEXT', 'NBAD-141',
                    f'HTTP POST (cleartext) to {req.get("host","unknown")}{req.get("uri","")[:50]} from {req.get("src_ip","")}',
                    mitre='T1040')

        # FTP
        ftp_flows = [(k, v) for k, v in self.flows.items() if len(k) == 5 and (k[2] in (20, 21) or k[3] in (20, 21))]
        if ftp_flows:
            self._add_anomaly('high', 'CLEARTEXT', 'NBAD-142',
                f'FTP cleartext detected: {len(ftp_flows)} flows — credentials transmitted in plaintext',
                mitre='T1040')

        # Telnet
        telnet_flows = [(k, v) for k, v in self.flows.items() if len(k) == 5 and (k[2] == 23 or k[3] == 23)]
        if telnet_flows:
            self._add_anomaly('high', 'CLEARTEXT', 'NBAD-143',
                f'Telnet cleartext detected: {len(telnet_flows)} flows — all data in cleartext',
                mitre='T1040')

        # POP3 / IMAP
        pop_flows = sum(1 for k in self.flows if len(k) == 5 and (k[2] in (110, 143) or k[3] in (110, 143)))
        if pop_flows:
            self._add_anomaly('medium', 'CLEARTEXT', 'NBAD-144',
                f'POP3/IMAP cleartext email: {pop_flows} flows — mail credentials in plaintext',
                mitre='T1040')

        # SNMP v1/v2 (community string in cleartext)
        snmp_flows = sum(1 for k in self.flows if len(k) == 5 and (k[2] in (161, 162) or k[3] in (161, 162)))
        if snmp_flows:
            self._add_anomaly('medium', 'CLEARTEXT', 'NBAD-145',
                f'SNMP v1/v2c cleartext: {snmp_flows} flows — community strings exposed',
                mitre='T1040')

        # LDAP (non-SSL)
        ldap_flows = sum(1 for k in self.flows if len(k) == 5 and (k[2] == 389 or k[3] == 389))
        if ldap_flows:
            self._add_anomaly('medium', 'CLEARTEXT', 'NBAD-146',
                f'LDAP cleartext: {ldap_flows} flows — directory queries unencrypted',
                mitre='T1040')

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-147 to 154: PROTOCOL ANOMALIES
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_tls_issues(self):
        """NBAD-147: Deprecated TLS / Weak Encryption. T1600"""
        weak_ciphers = {0x0004, 0x0005, 0x000a, 0x002f, 0x0035}  # RC4, DES, 3DES, RSA
        for hs in self.tls_handshakes:
            if hs.get('deprecated'):
                self._add_anomaly('high', 'PROTOCOL_ANOMALY', 'NBAD-147',
                    f'Deprecated {hs["version"]}: {hs.get("src_ip","")} → {hs.get("dst_ip","")} (SNI: {hs.get("sni","N/A")})',
                    mitre='T1600')

    def _detect_invalid_tcp_flags(self):
        """NBAD-148: Invalid TCP Flag Combinations. T1095"""
        for src, flag_counts in self.src_tcp_flags.items():
            for flags_str, count in flag_counts.items():
                # SYN+FIN is invalid (impossible in normal TCP)
                if 'SYN' in flags_str and 'FIN' in flags_str:
                    self._add_anomaly('high', 'PROTOCOL_ANOMALY', 'NBAD-148',
                        f'Invalid TCP SYN+FIN from {src}: {count} packets — evasion/scanning attempt',
                        mitre='T1095', source=src)
                # RST+SYN is also invalid
                elif 'RST' in flags_str and 'SYN' in flags_str:
                    self._add_anomaly('medium', 'PROTOCOL_ANOMALY', 'NBAD-148',
                        f'Invalid TCP RST+SYN from {src}: {count} packets',
                        mitre='T1095', source=src)

    def _detect_oversized_dns(self):
        """NBAD-149: Oversized DNS Queries (tunneling indicator). T1048"""
        for fk, fv in self.flows.items():
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp == 53 and proto == 'udp':
                    avg_pkt_size = fv['bytes'] / max(fv['packets'], 1)
                    if avg_pkt_size > 512:
                        self._add_anomaly('medium', 'PROTOCOL_ANOMALY', 'NBAD-149',
                            f'Oversized DNS packets: {src} → {dst} avg {avg_pkt_size:.0f} bytes (normal <512)',
                            mitre='T1048', source=src)

    def _detect_gre_tunneling(self):
        """NBAD-150: GRE Tunneling (covert channel). T1572"""
        for pkt in self.all_packets:
            ip = pkt.get('ip')
            if ip and ip.get('protocol') == 47:  # GRE
                src = ip.get('src_ip', '')
                dst = ip.get('dst_ip', '')
                if not _is_private(dst):
                    self._add_anomaly('high', 'PROTOCOL_ANOMALY', 'NBAD-150',
                        f'GRE tunnel to external: {src} → {dst} — possible protocol tunneling',
                        mitre='T1572', source=src)

    def _detect_socks_proxy(self):
        """NBAD-151: SOCKS Proxy Detection. T1090"""
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp in (1080, 1081, 9050) and proto == 'tcp':
                    self._add_anomaly('medium', 'PROTOCOL_ANOMALY', 'NBAD-151',
                        f'SOCKS proxy: {src} → {dst}:{dp} — possible traffic anonymization',
                        mitre='T1090', source=src)

    def _detect_http_connect_tunnel(self):
        """NBAD-152: HTTP CONNECT Tunneling. T1572"""
        for req in self.http_requests:
            if req.get('method') == 'CONNECT':
                self._add_anomaly('medium', 'PROTOCOL_ANOMALY', 'NBAD-152',
                    f'HTTP CONNECT tunnel: {req.get("src_ip","")} → {req.get("host","")} — proxy tunneling',
                    mitre='T1572', source=req.get('src_ip',''))

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-155 to 158: RANSOMWARE INDICATORS
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_ransomware(self):
        """NBAD-155: Ransomware C2 Port Detection. T1486"""
        ransomware_detected = set()
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if dp in RANSOMWARE_PORTS and dp not in ransomware_detected:
                db = MALICIOUS_PORTS_DB.get(dp, {})
                names = ', '.join(db.get('names', ['Ransomware'])[:3])
                self._add_anomaly('critical', 'RANSOMWARE', 'NBAD-155',
                    f'Ransomware C2 port {dp}: {src} → {dst} [{names}]',
                    mitre='T1486', source=src, destination=dst)
                self.iocs.append({'type': 'ransomware_c2', 'value': f'{dst}:{dp}'})
                ransomware_detected.add(dp)

        # File share encryption sweeps (rapid SMB writes)
        smb_write_src = defaultdict(set)
        for fk, fv in self.flows.items():
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp == 445 and fv['payload_bytes'] > 10240:  # >10KB SMB writes
                    smb_write_src[src].add(dst)

        for src, dsts in smb_write_src.items():
            if len(dsts) > 5:
                self._add_anomaly('critical', 'RANSOMWARE', 'NBAD-156',
                    f'Ransomware encryption sweep: {src} writing to {len(dsts)} SMB shares',
                    mitre='T1486', source=src)

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-159 to 163: THREAT ACTOR PATTERNS
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_threat_actor_ports(self):
        """NBAD-159: Threat Actor / APT Port Indicators. T1071"""
        alerted = set()
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if dp in THREAT_ACTOR_PORTS and dp not in alerted:
                db = MALICIOUS_PORTS_DB.get(dp, {})
                names = ', '.join(db.get('names', ['Threat Actor'])[:3])
                self._add_anomaly('critical', 'THREAT_ACTOR', 'NBAD-159',
                    f'Threat actor port {dp} [{names}]: {src} → {dst}',
                    mitre='T1071', source=src, destination=dst)
                self.iocs.append({'type': 'threat_actor_port', 'value': f'{dp} ({names})'})
                alerted.add(dp)

        # Rootkit ports
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if dp in ROOTKIT_PORTS and dp not in alerted:
                db = MALICIOUS_PORTS_DB.get(dp, {})
                names = ', '.join(db.get('names', ['Rootkit'])[:3])
                self._add_anomaly('critical', 'THREAT_ACTOR', 'NBAD-160',
                    f'Rootkit port {dp} [{names}]: {src} → {dst}',
                    mitre='T1014', source=src, destination=dst)
                alerted.add(dp)

    # ══════════════════════════════════════════════════════════════════════════
    # RAT FAMILY DETECTION
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_rat_families(self):
        """NBAD-RAT: RAT Family Multi-Port Pattern Matching. T1219"""
        active_ports = set()
        for fk in self.flows:
            if len(fk) == 5:
                active_ports.add(fk[2])
                active_ports.add(fk[3])

        for rat_name, rat_data in RAT_FAMILIES.items():
            matches = active_ports & rat_data['ports']
            if len(matches) >= 2:
                # Find involved IPs
                involved = set()
                for fk in self.flows:
                    if len(fk) == 5 and (fk[2] in matches or fk[3] in matches):
                        involved.add(fk[0])
                        involved.add(fk[1])

                self._add_anomaly('critical', 'RAT_DETECTION', f'NBAD-RAT-{rat_name}',
                    f'{rat_name} detected: {len(matches)} matching ports {sorted(matches)} — {rat_data["desc"]}',
                    mitre='T1219')
                self.iocs.append({'type': 'rat_detection', 'value': rat_name})

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-170 to 176: ADVANCED EXPLOITATION
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_proxyshell(self):
        """NBAD-170: ProxyShell / Exchange Server RCE. T1190"""
        proxyshell_paths = [
            '/autodiscover/autodiscover.json', '/mapi/nspi/',
            '/ecp/', '/ews/exchange.asmx',
        ]
        for req in self.http_requests:
            uri = req.get('uri', '').lower()
            host = req.get('host', '')
            if any(p in uri for p in proxyshell_paths):
                if req.get('method') in ('POST', 'PUT'):
                    self._add_anomaly('critical', 'EXPLOITATION', 'NBAD-170',
                        f'ProxyShell/Exchange RCE attempt: {req.get("src_ip","")} -> {host}{uri[:60]}',
                        mitre='T1190', source=req.get('src_ip',''))
                    self.iocs.append({'type': 'exploit_url', 'value': f'{host}{uri}'})

    def _detect_spring4shell(self):
        """NBAD-171: Spring4Shell / SpringShell RCE. T1190"""
        spring_patterns = [
            'class.module.classloader', 'class.module.class',
            '.getclassloader()', 'classloader.urls',
        ]
        for req in self.http_requests:
            payload = (req.get('uri', '') + req.get('payload', '')).lower()
            if any(p in payload for p in spring_patterns):
                self._add_anomaly('critical', 'EXPLOITATION', 'NBAD-171',
                    f'Spring4Shell exploitation: {req.get("src_ip","")} -> {req.get("host","")}',
                    mitre='T1190', source=req.get('src_ip',''))

    def _detect_xxe_ssrf(self):
        """NBAD-172: XXE / SSRF Injection. T1190"""
        xxe_patterns  = [b'<!entity', b'<!doctype', b'file:///', b'expect://', b'php://']
        ssrf_patterns = [b'169.254.169.254', b'localhost', b'127.0.0.1', b'::1',
                         b'metadata.google.internal', b'instance-data']
        for pkt in self.all_packets:
            tcp = pkt.get('tcp')
            if not tcp: continue
            payload = tcp.get('payload', b'')
            if not payload: continue
            payload_l = payload.lower()
            for pat in xxe_patterns:
                if pat in payload_l:
                    ip = pkt.get('ip', {})
                    self._add_anomaly('high', 'EXPLOITATION', 'NBAD-172',
                        f'XXE injection payload from {ip.get("src_ip","")}: contains {pat.decode()}',
                        mitre='T1190', source=ip.get('src_ip',''))
                    break
            for pat in ssrf_patterns:
                if pat in payload_l:
                    ip = pkt.get('ip', {})
                    dst = ip.get('dst_ip', '')
                    self._add_anomaly('high', 'EXPLOITATION', 'NBAD-172',
                        f'SSRF probe from {ip.get("src_ip","")}: target {pat.decode()} in payload',
                        mitre='T1190', source=ip.get('src_ip',''))
                    break

    def _detect_deserialization(self):
        """NBAD-173: Java / .NET Deserialization Attack Payloads. T1190"""
        deser_sigs = [
            b'\xac\xed\x00\x05',  # Java serialized object magic bytes
            b'rO0AB',               # Base64 Java serialization
            b'AAEAAAD',             # .NET BinaryFormatter
            b'ysoserial',           # ysoserial payload marker
            b'Runtime.getRuntime',  # Java runtime exec
            b'ProcessBuilder',
        ]
        for pkt in self.all_packets:
            tcp = pkt.get('tcp')
            if not tcp: continue
            payload = tcp.get('payload', b'')
            if not payload: continue
            for sig in deser_sigs:
                if sig in payload:
                    ip = pkt.get('ip', {})
                    self._add_anomaly('critical', 'EXPLOITATION', 'NBAD-173',
                        f'Deserialization attack payload from {ip.get("src_ip","")}: {sig[:20]}',
                        mitre='T1190', source=ip.get('src_ip',''))
                    self.iocs.append({'type': 'deser_payload', 'value': ip.get('src_ip','')})
                    break

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-177 to 181: LAYER 2 ADVANCED
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_dhcp_starvation(self):
        """NBAD-177: DHCP Starvation / Rogue DHCP. T1557"""
        dhcp_src_macs = defaultdict(int)
        for pkt in self.all_packets:
            udp = pkt.get('udp')
            if not udp: continue
            src_port = udp.get('src_port', 0)
            dst_port = udp.get('dst_port', 0)
            if src_port == 68 and dst_port == 67:  # DHCP Discover/Request
                eth = pkt.get('eth', {})
                mac = eth.get('src_mac', '')
                if mac:
                    dhcp_src_macs[mac] += 1

        total_dhcp = sum(dhcp_src_macs.values())
        unique_macs = len(dhcp_src_macs)
        if unique_macs > 20 or total_dhcp > 50:
            self._add_anomaly('high', 'LAYER2_ATTACK', 'NBAD-177',
                f'DHCP starvation: {total_dhcp} DHCP requests from {unique_macs} unique MACs',
                mitre='T1557')

    def _detect_stp_manipulation(self):
        """NBAD-178: Spanning Tree Protocol (STP) Manipulation. T1557"""
        stp_count = defaultdict(int)
        for pkt in self.all_packets:
            eth = pkt.get('eth', {})
            # STP uses multicast MAC 01:80:c2:00:00:00 and ethertype 0x0026 or raw LLC
            dst_mac = eth.get('dst_mac', '').lower()
            if dst_mac == '01:80:c2:00:00:00':
                src_mac = eth.get('src_mac', '')
                stp_count[src_mac] += 1

        for src_mac, count in stp_count.items():
            if count > 10:
                self._add_anomaly('high', 'LAYER2_ATTACK', 'NBAD-178',
                    f'STP manipulation from MAC {src_mac}: {count} STP frames — possible root bridge attack',
                    mitre='T1557')

    def _detect_vlan_hopping(self):
        """NBAD-179: VLAN Hopping via Double Tagging. T1557"""
        double_tagged = 0
        for pkt in self.all_packets:
            eth = pkt.get('eth', {})
            # Double-tagged frames have ethertype 0x8100 (VLAN) inside another 0x8100
            if eth.get('ethertype') == 0x8100:
                inner = eth.get('inner_ethertype', 0)
                if inner == 0x8100:
                    double_tagged += 1

        if double_tagged > 5:
            self._add_anomaly('high', 'LAYER2_ATTACK', 'NBAD-179',
                f'VLAN hopping: {double_tagged} double-tagged 802.1Q frames detected',
                mitre='T1557')

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-182 to 186: ADVANCED EXFILTRATION
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_smtp_exfil(self):
        """NBAD-182: SMTP Data Exfiltration. T1048.002"""
        smtp_flows = [(k, v) for k, v in self.flows.items()
                      if len(k) == 5 and k[3] in (25, 587, 465)]
        for fk, fv in smtp_flows:
            src, dst = fk[0], fk[1]
            if fv['payload_bytes'] > 1_000_000:  # >1MB over SMTP
                self._add_anomaly('high', 'EXFILTRATION', 'NBAD-182',
                    f'SMTP exfil: {src} sent {_human_bytes(fv["payload_bytes"])} to {dst}:{fk[3]}',
                    mitre='T1048.002', source=src, destination=dst)
                self.iocs.append({'type': 'smtp_exfil', 'value': f'{src}->{dst}'})

    def _detect_ftp_exfil(self):
        """NBAD-183: FTP Data Exfiltration. T1048.003"""
        ftp_flows = [(k, v) for k, v in self.flows.items()
                     if len(k) == 5 and k[3] in (20, 21)]
        large_ftp = [(k, v) for k, v in ftp_flows if not _is_private(k[1]) and v['bytes'] > 500_000]
        if large_ftp:
            for fk, fv in large_ftp[:3]:
                self._add_anomaly('high', 'EXFILTRATION', 'NBAD-183',
                    f'FTP exfil to external: {fk[0]} -> {fk[1]} transferred {_human_bytes(fv["bytes"])}',
                    mitre='T1048.003', source=fk[0], destination=fk[1])
                self.iocs.append({'type': 'ftp_exfil_dst', 'value': fk[1]})

    def _detect_cloud_exfil(self):
        """NBAD-184: Cloud Storage Exfiltration Indicators. T1567"""
        cloud_domains = [
            'pastebin.com', 'paste.ee', 'hastebin.com', 'transfer.sh',
            'mega.nz', 'anonfiles.com', 'temp.sh', 'filebin.net',
            'gofile.io', 'pixeldrain.com', 'file.io', 'wetransfer.com',
            '0x0.st', 'uguu.se', 'nopaste.ml', 'paste.c-net.org',
        ]
        for req in self.http_requests:
            host = req.get('host', '').lower()
            method = req.get('method', '')
            if any(d in host for d in cloud_domains):
                if method in ('POST', 'PUT'):
                    self._add_anomaly('high', 'EXFILTRATION', 'NBAD-184',
                        f'Cloud/paste exfil: {req.get("src_ip","")} {method} -> {host}',
                        mitre='T1567', source=req.get('src_ip',''))
                    self.iocs.append({'type': 'cloud_exfil', 'value': host})

        # DNS-based cloud exfil (very long subdomains to cloud provider NS)
        for q in self.dns_queries:
            name = q.get('name', '')
            if any(c in name for c in cloud_domains):
                if len(name) > 100:
                    self._add_anomaly('medium', 'EXFILTRATION', 'NBAD-184',
                        f'Long cloud DNS query (possible exfil): {name[:80]}',
                        mitre='T1567')

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-187 to 190: C2 ADVANCED
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_domain_fronting(self):
        """NBAD-187: Domain Fronting Detection. T1090.004"""
        # Domain fronting: SNI host != HTTP Host header
        sni_per_flow = {}
        for hs in self.tls_handshakes:
            flow_key = (hs.get('src_ip',''), hs.get('dst_ip',''))
            if hs.get('sni'):
                sni_per_flow[flow_key] = hs['sni']

        for req in self.http_requests:
            host   = req.get('host', '').lower()
            src_ip = req.get('src_ip', '')
            fk     = (src_ip, req.get('dst_ip', ''))
            sni    = sni_per_flow.get(fk, '')
            if sni and host and sni.lower() != host:
                if not sni.endswith(host) and not host.endswith(sni):
                    self._add_anomaly('high', 'C2_BEACONING', 'NBAD-187',
                        f'Domain fronting: SNI={sni} but HTTP Host={host} — CDN C2 evasion',
                        mitre='T1090.004', source=src_ip)
                    self.iocs.append({'type': 'domain_fronting', 'value': f'{sni}->{host}'})

    def _detect_long_lived_sessions(self):
        """NBAD-188: Long-Lived Sessions (C2/RAT indicator). T1071"""
        THRESHOLD_SECS = 3600  # >1 hour
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            duration = fv['end'] - fv['start']
            if duration > THRESHOLD_SECS and proto == 'tcp' and not _is_private(dst):
                self._add_anomaly('medium', 'C2_BEACONING', 'NBAD-188',
                    f'Long-lived session: {src} -> {dst}:{dp} ({proto}) lasted '
                    f'{int(duration//3600)}h {int((duration%3600)//60)}m — possible persistent C2',
                    mitre='T1071', source=src, destination=dst)

    def _detect_port_knocking(self):
        """NBAD-189: Port Knocking Pattern Detection. T1571"""
        # Port knocking: sequential single-packet SYNs to closed ports with no response
        src_knock = defaultdict(list)
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if proto == 'tcp' and fv['syn_count'] == 1 and fv['packets'] <= 2 and fv['rst_count'] >= 1:
                src_knock[(src, dst)].append((dp, fv['start']))

        for (src, dst), knocks in src_knock.items():
            if len(knocks) >= 4:
                knocks_sorted = sorted(knocks, key=lambda x: x[1])
                ports_seq = [k[0] for k in knocks_sorted[:6]]
                self._add_anomaly('medium', 'C2_BEACONING', 'NBAD-189',
                    f'Port knocking pattern: {src} -> {dst} sequence {ports_seq}',
                    mitre='T1571', source=src, destination=dst)

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-191 to 194: CREDENTIAL ATTACKS ADVANCED
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_asrep_roasting(self):
        """NBAD-191: AS-REP Roasting (Kerberos pre-auth disabled). T1558.004"""
        krb_src = defaultdict(int)
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if dp == 88 and proto in ('tcp', 'udp'):
                krb_src[src] += fv['packets']

        # Multiple Kerberos auth requests from one host in short time = roasting
        for src, count in krb_src.items():
            if count > 20:
                self._add_anomaly('high', 'AUTH_ATTACK', 'NBAD-191',
                    f'AS-REP/Kerberoast: {src} sent {count} Kerberos (port 88) packets — possible pre-auth attack',
                    mitre='T1558.004', source=src)

    def _detect_ldap_brute_force(self):
        """NBAD-192: LDAP Brute Force / Enumeration. T1110.001"""
        ldap_src = defaultdict(set)
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp in (389, 636, 3268, 3269):
                    ldap_src[src].add(dst)

        for src, dsts in ldap_src.items():
            if len(dsts) > 5:
                self._add_anomaly('high', 'AUTH_ATTACK', 'NBAD-192',
                    f'LDAP brute/enum: {src} queried {len(dsts)} AD servers on LDAP/LDAPS',
                    mitre='T1110.001', source=src)

    def _detect_smb_brute_force(self):
        """NBAD-193: SMB Authentication Brute Force. T1110.001"""
        smb_attempts = defaultdict(set)
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if dp == 445 and fv['packets'] < 10 and fv['rst_count'] > 0:
                smb_attempts[src].add(dst)

        for src, dsts in smb_attempts.items():
            if len(dsts) > 5:
                self._add_anomaly('high', 'AUTH_ATTACK', 'NBAD-193',
                    f'SMB brute force: {src} -> {len(dsts)} hosts with RST responses',
                    mitre='T1110.001', source=src)

    def _detect_ntlm_relay(self):
        """NBAD-194: NTLM Relay Attack Indicators. T1557.001"""
        # NTLM relay: traffic forwarded SMB -> SMB or SMB -> HTTP rapidly
        smb_src_dst = {}
        for fk, fv in self.flows.items():
            if len(fk) == 5 and fk[3] == 445:
                src, dst = fk[0], fk[1]
                smb_src_dst[src] = smb_src_dst.get(src, set())
                smb_src_dst[src].add(dst)

        for src, dsts in smb_src_dst.items():
            if len(dsts) > 3 and not _is_private(src):
                self._add_anomaly('critical', 'AUTH_ATTACK', 'NBAD-194',
                    f'NTLM relay indicator: external {src} initiated SMB to {len(dsts)} internal hosts',
                    mitre='T1557.001', source=src)

    # ══════════════════════════════════════════════════════════════════════════
    # NBAD-195 to 199: MALWARE BEHAVIORAL
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_worm_propagation(self):
        """NBAD-195: Worm Propagation Pattern. T1210"""
        # Worm hallmark: one host initiates identical flows to many different hosts
        # on the same destination port in a short time window
        worm_candidates = defaultdict(lambda: defaultdict(int))
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if _is_private(src) and fv['bytes'] < 50000:  # Small payload to many hosts
                worm_candidates[src][dp] += 1

        worm_ports = {21, 22, 23, 80, 135, 139, 445, 1433, 3389, 5900}
        for src, port_counts in worm_candidates.items():
            for dp, count in port_counts.items():
                if count > 20 and dp in worm_ports:
                    db = MALICIOUS_PORTS_DB.get(dp, {})
                    names = [n for n in db.get('names', [])
                             if 'worm' in n.lower() or any(t == 'Worm' for t in db.get('types', []))]
                    hint = f' [{", ".join(names[:2])}]' if names else ''
                    self._add_anomaly('critical', 'MALWARE_BEHAVIOR', 'NBAD-195',
                        f'Worm propagation: {src} probed port {dp} on {count} hosts{hint}',
                        mitre='T1210', source=src)
                    self.iocs.append({'type': 'worm_src', 'value': src})

    def _detect_p2p_activity(self):
        """NBAD-196: P2P / File Sharing Activity. T1071"""
        # P2P ports from threat intel DB
        p2p_ports_db = {port for port, d in MALICIOUS_PORTS_DB.items()
                        if 'P2P' in d.get('types', [])}
        p2p_ports_db.update({6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889,
                              4662, 4672, 1214, 51413})  # BitTorrent/eMule/Kazaa ranges

        detected_p2p = set()
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if dp in p2p_ports_db and dp not in detected_p2p:
                    db = MALICIOUS_PORTS_DB.get(dp, {})
                    names = ', '.join(db.get('names', ['P2P'])[:2])
                    self._add_anomaly('low', 'MALWARE_BEHAVIOR', 'NBAD-196',
                        f'P2P activity: port {dp} [{names}] from {src}',
                        mitre='T1071', source=src)
                    detected_p2p.add(dp)

    def _detect_phishing_ports(self):
        """NBAD-197: Phishing Campaign Infrastructure. T1566"""
        phishing_ports_db = {port for port, d in MALICIOUS_PORTS_DB.items()
                             if 'Phishing Campaign' in d.get('types', [])}
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if dp in phishing_ports_db:
                db = MALICIOUS_PORTS_DB.get(dp, {})
                names = ', '.join(db.get('names', ['Phishing'])[:3])
                self._add_anomaly('critical', 'MALWARE_BEHAVIOR', 'NBAD-197',
                    f'Phishing infrastructure port {dp} [{names}]: {src} -> {dst}',
                    mitre='T1566', source=src, destination=dst)
                self.iocs.append({'type': 'phishing_port', 'value': f'{dst}:{dp}'})

    def _detect_spyware_ports(self):
        """NBAD-198: Spyware / Surveillance Tool Ports. T1219"""
        spyware_ports_db = {port for port, d in MALICIOUS_PORTS_DB.items()
                            if 'Spyware' in d.get('types', [])}
        detected = set()
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if dp in spyware_ports_db and dp not in detected:
                db = MALICIOUS_PORTS_DB.get(dp, {})
                names = ', '.join(db.get('names', ['Spyware'])[:3])
                # Only alert on external destinations
                if not _is_private(dst):
                    self._add_anomaly('high', 'MALWARE_BEHAVIOR', 'NBAD-198',
                        f'Spyware port {dp} to external [{names}]: {src} -> {dst}',
                        mitre='T1219', source=src, destination=dst)
                    self.iocs.append({'type': 'spyware_port', 'value': f'{dst}:{dp}'})
                    detected.add(dp)

    def _detect_multi_stage_attack(self):
        """NBAD-199: Multi-Stage Attack Correlation. T1059"""
        # Correlate: recon + C2 + exfil from same source = sophisticated attack
        categories_per_src = defaultdict(set)
        for a in self.anomalies:
            src = a.get('source', '')
            cat = a.get('category', '')
            if src:
                categories_per_src[src].add(cat)

        stage_map = {
            'RECONNAISSANCE': 1, 'AUTH_ATTACK': 2, 'LATERAL_MOVEMENT': 3,
            'C2_BEACONING': 4, 'EXFILTRATION': 5, 'RANSOMWARE': 6,
        }
        for src, cats in categories_per_src.items():
            stages = {stage_map[c] for c in cats if c in stage_map}
            if len(stages) >= 3:
                cat_list = sorted(cats & set(stage_map.keys()))
                self._add_anomaly('critical', 'MULTI_STAGE', 'NBAD-199',
                    f'Multi-stage attack from {src}: observed {len(stages)} kill-chain stages: '
                    f'{" -> ".join(cat_list[:4])}',
                    mitre='T1059', source=src)
                self.iocs.append({'type': 'apt_source', 'value': src})


    # ══════════════════════════════════════════════════════════════════════════
    # NABD DOCX — NEW DETECTIONS FROM INPUT DOCUMENT
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_tcp_connect_scan(self):
        """NABD-31: TCP Connect Scan (full 3-way handshake scan). T1046"""
        full_connect = defaultdict(set)
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if proto == 'tcp' and fv['syn_count'] >= 1 and fv['ack_count'] >= 1 and fv['rst_count'] >= 1:
                full_connect[src].add(dp)
        for src, ports in full_connect.items():
            if len(ports) > 15:
                self._add_anomaly('high', 'RECONNAISSANCE', 'NABD-31',
                    f'TCP Connect scan from {src}: {len(ports)} ports with full handshake+RST',
                    mitre='T1046', source=src,
                    extra={'src_ip': src, 'attack_name': 'TCP Connect Scan', 'unique_ports': len(ports)})
                self.iocs.append({'type': 'scanner_ip', 'value': src})

    def _detect_tcp_ack_scan(self):
        """NABD-32: TCP ACK Scan for firewall mapping. T1046"""
        ack_scanners = defaultdict(set)
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            # Pure ACK with no prior SYN = firewall mapping
            if proto == 'tcp' and fv.get('ack_count', 0) > 0 and fv.get('syn_count', 0) == 0:
                ack_scanners[src].add(dp)
        for src, ports in ack_scanners.items():
            if len(ports) > 10:
                self._add_anomaly('high', 'RECONNAISSANCE', 'NABD-32',
                    f'TCP ACK scan (firewall mapping) from {src}: {len(ports)} ports probed — identifies filtered vs unfiltered paths',
                    mitre='T1046', source=src,
                    extra={'src_ip': src, 'attack_name': 'TCP ACK Scan (Firewall Map)', 'unique_ports': len(ports)})

    def _detect_slow_service_enum(self):
        """NABD-33: Slow Service Enumeration (APT/red-team style). T1046"""
        # Long session, tiny payload = banner grabbing only
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            duration = fv['end'] - fv['start']
            avg_payload = fv.get('payload_bytes', 0) / max(fv['packets'], 1)
            if duration > 30 and avg_payload < 50 and fv['packets'] < 10 and not _is_private(src):
                self._add_anomaly('medium', 'RECONNAISSANCE', 'NABD-33',
                    f'Slow service enumeration: {src} -> {dst}:{dp} — {duration:.0f}s session, only {avg_payload:.0f}B avg payload (banner grab)',
                    mitre='T1046', source=src, destination=dst,
                    extra={'src_ip': src, 'dst_ip': dst, 'dst_port': dp, 'attack_name': 'Slow Service Enum',
                           'session_duration': duration})

    def _detect_web_dir_bruteforce(self):
        """NABD-35: Web Directory Brute Force (forced browsing). T1083"""
        host_404s = defaultdict(int)
        host_srcs = defaultdict(set)
        for req in self.http_requests:
            host = req.get('host', '')
            src  = req.get('src_ip', '')
            # 404 responses imply failed directory enumeration
            if host:
                host_404s[f'{src}->{host}'] += 1
                host_srcs[src].add(req.get('uri', ''))
        for src, uris in host_srcs.items():
            if len(uris) > 30:
                self._add_anomaly('high', 'RECONNAISSANCE', 'NABD-35',
                    f'Web directory brute force from {src}: {len(uris)} unique URIs probed',
                    mitre='T1083', source=src,
                    extra={'src_ip': src, 'attack_name': 'Web Directory BruteForce', 'uri_count': len(uris)})
                self.iocs.append({'type': 'web_scanner', 'value': src})

    def _detect_low_slow_password_spray(self):
        """NABD-34: Low-and-Slow Password Spraying. T1110.003"""
        # Many destination hosts from same src on auth ports, spread over time
        auth_ports = {22, 23, 25, 80, 110, 143, 389, 443, 445, 636, 1433, 3389}
        src_host_spray = defaultdict(set)
        src_times = defaultdict(list)
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if dp in auth_ports and _is_private(src):
                src_host_spray[src].add(dst)
                src_times[src].append(fv['start'])
        for src, hosts in src_host_spray.items():
            if len(hosts) > 8:
                times = sorted(src_times[src])
                spread = times[-1] - times[0] if len(times) > 1 else 0
                # Spread over many seconds = slow spray
                if spread > 60:
                    self._add_anomaly('high', 'AUTH_ATTACK', 'NABD-34',
                        f'Low-and-slow password spray: {src} targeted {len(hosts)} hosts over {spread:.0f}s — evades volume thresholds',
                        mitre='T1110.003', source=src,
                        extra={'src_ip': src, 'attack_name': 'Low-Slow Password Spray',
                               'target_count': len(hosts), 'spread_seconds': spread})

    def _detect_ntlm_downgrade(self):
        """NABD-36: NTLM Downgrade Attack (NTLMv1). T1557.001"""
        # Look for SMB traffic with very small auth packets (NTLMv1 shorter than NTLMv2)
        smb_tiny_auth = defaultdict(int)
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if dp == 445 and proto == 'tcp':
                # NTLMv1 auth blob is smaller — avg payload under 100 bytes per packet on short sessions
                avg_pkt = fv.get('payload_bytes', 0) / max(fv['packets'], 1)
                if 10 < avg_pkt < 80 and fv['packets'] < 8:
                    smb_tiny_auth[src] += 1
        for src, count in smb_tiny_auth.items():
            if count > 3:
                self._add_anomaly('critical', 'AUTH_ATTACK', 'NABD-36',
                    f'NTLM downgrade indicator: {src} — {count} short SMB auth sessions (possible NTLMv1 negotiation)',
                    mitre='T1557.001', source=src,
                    extra={'src_ip': src, 'attack_name': 'NTLM Downgrade (NTLMv1)', 'smb_flows': count})

    def _detect_buffer_overflow(self):
        """NABD-38: Buffer Overflow Payload Patterns. T1190"""
        overflow_sigs = [
            b'\x90' * 16,         # NOP sled
            b'A' * 100,            # Classic overflow filler
            b'\x41' * 50,         # Hex A overflow
            b'\xcc' * 8,          # INT3 breakpoint
            b'\xeb\x06',         # JMP short shellcode entry
        ]
        for pkt in self.all_packets:
            tcp = pkt.get('tcp')
            if not tcp: continue
            payload = tcp.get('payload', b'')
            if len(payload) < 50: continue
            for sig in overflow_sigs:
                if sig in payload:
                    ip = pkt.get('ip', {})
                    src = ip.get('src_ip', '')
                    dst = ip.get('dst_ip', '')
                    self._add_anomaly('critical', 'EXPLOITATION', 'NABD-38',
                        f'Buffer overflow pattern from {src}: NOP sled / filler sequence detected in payload',
                        mitre='T1190', source=src, destination=dst,
                        extra={'src_ip': src, 'dst_ip': dst, 'attack_name': 'Buffer Overflow Attempt'})
                    self.iocs.append({'type': 'exploit_src', 'value': src})
                    break

    def _detect_exploit_kit_traffic(self):
        """NABD-39: Exploit Kit Traffic Patterns. T1189"""
        # EK indicators: landing page → redirect → payload download pattern
        ek_uris = [
            '/gate.php', '/panel/', '/count.php', '/load.php',
            '/bot.php', '/config.bin', '/loader.php', '/update.php',
        ]
        ek_ua_patterns = [
            'compatible; MSIE 6', 'compatible; MSIE 7', 'compatible; MSIE 8',
            'Trident/4.0', 'Trident/5.0',  # Old IE - common EK target
        ]
        for req in self.http_requests:
            uri  = req.get('uri', '').lower()
            ua   = req.get('user_agent', '').lower()
            src  = req.get('src_ip', '')
            host = req.get('host', '')
            if any(e in uri for e in ek_uris):
                self._add_anomaly('critical', 'EXPLOITATION', 'NABD-39',
                    f'Exploit kit URI pattern: {src} -> {host}{uri[:60]} — potential drive-by compromise',
                    mitre='T1189', source=src,
                    extra={'src_ip': src, 'dst_ip': host, 'attack_name': 'Exploit Kit Traffic', 'uri': uri})
                self.iocs.append({'type': 'ek_url', 'value': f'http://{host}{uri}'})
            if any(p in ua for p in ek_ua_patterns) and not _is_private(req.get('dst_ip', '0.0.0.0')):
                self._add_anomaly('medium', 'EXPLOITATION', 'NABD-39',
                    f'Old browser UA (EK target): {src} — UA: {ua[:80]}',
                    mitre='T1189', source=src,
                    extra={'src_ip': src, 'attack_name': 'Old Browser (EK Target)', 'user_agent': ua[:80]})

    def _detect_malicious_payload_download(self):
        """NABD-40: Malicious Payload Download Indicators. T1105"""
        pe_magic   = b'MZ'       # Windows PE
        elf_magic  = b'\x7fELF'  # Linux ELF
        jar_magic  = b'PK\x03\x04'  # JAR/ZIP
        ps_sigs    = [b'powershell', b'IEX(', b'Invoke-Expression', b'FromBase64String']
        for req in self.http_requests:
            src  = req.get('src_ip', '')
            host = req.get('host', '')
            uri  = req.get('uri', '').lower()
            if any(uri.endswith(ext) for ext in ('.exe', '.dll', '.bat', '.ps1', '.vbs', '.hta', '.jar', '.sh', '.elf')):
                self._add_anomaly('critical', 'EXPLOITATION', 'NABD-40',
                    f'Executable download: {src} <- {host}{uri[:60]}',
                    mitre='T1105', source=src,
                    extra={'src_ip': src, 'dst_ip': host, 'attack_name': 'Payload Download', 'uri': uri})
                self.iocs.append({'type': 'payload_url', 'value': f'http://{host}{uri}'})
        for pkt in self.all_packets:
            tcp = pkt.get('tcp')
            if not tcp: continue
            payload = tcp.get('payload', b'')
            if len(payload) < 4: continue
            if payload[:2] == pe_magic:
                ip = pkt.get('ip', {})
                self._add_anomaly('critical', 'EXPLOITATION', 'NABD-40',
                    f'PE binary transfer: {ip.get("src_ip","")} -> {ip.get("dst_ip","")} (Windows executable in stream)',
                    mitre='T1105', source=ip.get('src_ip',''),
                    extra={'src_ip': ip.get('src_ip',''), 'dst_ip': ip.get('dst_ip',''),
                           'attack_name': 'PE Binary Transfer'})

    def _detect_http_smuggling(self):
        """NABD-41: HTTP Request Smuggling / Desync. T1190"""
        smuggling_sigs = [b'Transfer-Encoding: chunked', b'Content-Length:', b'HTTP/1.1 ']
        for pkt in self.all_packets:
            tcp = pkt.get('tcp')
            if not tcp: continue
            payload = tcp.get('payload', b'')
            if len(payload) < 30: continue
            payload_l = payload.lower()
            # Conflicting Content-Length AND Transfer-Encoding in same request
            has_cl = b'content-length:' in payload_l
            has_te = b'transfer-encoding:' in payload_l
            if has_cl and has_te:
                ip = pkt.get('ip', {})
                src = ip.get('src_ip', '')
                self._add_anomaly('critical', 'EXPLOITATION', 'NABD-41',
                    f'HTTP request smuggling: {src} — conflicting Content-Length + Transfer-Encoding headers',
                    mitre='T1190', source=src,
                    extra={'src_ip': src, 'attack_name': 'HTTP Smuggling/Desync'})
                self.iocs.append({'type': 'smuggling_src', 'value': src})
                break

    def _detect_fileless_exploitation(self):
        """NABD-42: Fileless / Living-off-the-Land Exploitation. T1059.001"""
        fileless_patterns = [
            b'powershell -enc', b'powershell -e ', b'powershell -nop',
            b'powershell -w hidden', b'IEX(', b'Invoke-Expression',
            b'FromBase64String', b'-EncodedCommand',
            b'cmd.exe /c', b'wscript.exe', b'cscript.exe',
            b'regsvr32 /s /n /u /i:', b'mshta http',
        ]
        for pkt in self.all_packets:
            tcp = pkt.get('tcp')
            if not tcp: continue
            payload = tcp.get('payload', b'')
            if not payload: continue
            payload_l = payload.lower()
            for sig in fileless_patterns:
                if sig.lower() in payload_l:
                    ip = pkt.get('ip', {})
                    src = ip.get('src_ip', '')
                    self._add_anomaly('critical', 'EXPLOITATION', 'NABD-42',
                        f'Fileless/LOTL attack: {src} — "{sig.decode(errors="replace")}" in payload',
                        mitre='T1059.001', source=src,
                        extra={'src_ip': src, 'attack_name': 'Fileless (PowerShell/LOTL)',
                               'indicator': sig.decode(errors='replace')})
                    self.iocs.append({'type': 'lotl_src', 'value': src})
                    break

    def _detect_tls_cert_abuse(self):
        """NABD-43: TLS Certificate Abuse (self-signed, long validity). T1573"""
        # Check for anomalous TLS sessions to non-standard ports with unusual handshake
        c2_non_443_tls = defaultdict(int)
        for fk in self.flows:
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if proto == 'tcp' and dp not in (443, 8443, 8080, 465, 993, 995, 636, 5061) and dp > 1024:
                # Check if any TLS handshake was seen on this flow
                for hs in self.tls_handshakes:
                    if hs.get('src_ip') == src and not _is_private(dst):
                        c2_non_443_tls[f'{src}->{dst}:{dp}'] += 1
        for flow, count in c2_non_443_tls.items():
            if count > 0:
                self._add_anomaly('high', 'C2_BEACONING', 'NABD-43',
                    f'TLS on non-standard port: {flow} — possible C2 using TLS for evasion',
                    mitre='T1573', source=flow.split('->')[0],
                    extra={'attack_name': 'TLS Cert Abuse / Non-std Port TLS', 'flow': flow})

    def _detect_http_header_covert(self):
        """NABD-44: HTTP Header Covert Channel (data in User-Agent/Cookie). T1071.001"""
        ENTROPY_THRESHOLD = 3.8
        LONG_UA_THRESHOLD = 200
        for req in self.http_requests:
            ua   = req.get('user_agent', '')
            src  = req.get('src_ip', '')
            host = req.get('host', '')
            # Very long or high-entropy UA = possible covert channel
            if len(ua) > LONG_UA_THRESHOLD:
                ent = _entropy(ua)
                if ent > ENTROPY_THRESHOLD:
                    self._add_anomaly('high', 'C2_BEACONING', 'NABD-44',
                        f'Covert HTTP header: {src} -> {host} — User-Agent entropy={ent:.2f}, len={len(ua)} (data hidden in header)',
                        mitre='T1071.001', source=src,
                        extra={'src_ip': src, 'dst_ip': host, 'attack_name': 'HTTP Header Covert Channel',
                               'ua_entropy': ent, 'ua_len': len(ua)})

    def _detect_doh_dot_abuse(self):
        """NABD-45: DNS-over-HTTPS/TLS Abuse for C2. T1071.004"""
        # DoH: small frequent POSTs to port 443 to known DoH providers OR unknown IPs
        known_doh = {'1.1.1.1', '8.8.8.8', '9.9.9.9', '149.112.112.112', '208.67.222.222'}
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if dp == 443 and proto == 'tcp' and dst not in known_doh and not _is_private(dst):
                avg_size = fv.get('payload_bytes', 0) / max(fv['packets'], 1)
                # Many small requests = DoH-style C2
                if fv['packets'] > 20 and avg_size < 200:
                    self._add_anomaly('medium', 'C2_BEACONING', 'NABD-45',
                        f'Possible DoH/DoT C2: {src} -> {dst}:443 — {fv["packets"]} pkts, avg {avg_size:.0f}B (encrypted DNS-style C2)',
                        mitre='T1071.004', source=src, destination=dst,
                        extra={'src_ip': src, 'dst_ip': dst, 'attack_name': 'DoH/DoT C2 Abuse',
                               'pkt_count': fv['packets'], 'avg_size': avg_size})

    def _detect_smb_tree_abuse(self):
        """NABD-46: SMB Tree Connect / IPC$ Abuse. T1021.002"""
        smb_ipc_src = defaultdict(set)
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if dp == 445 and proto == 'tcp' and fv['packets'] > 4:
                smb_ipc_src[src].add(dst)
        for src, dsts in smb_ipc_src.items():
            if len(dsts) > 4 and _is_private(src):
                self._add_anomaly('high', 'LATERAL_MOVEMENT', 'NABD-46',
                    f'SMB tree abuse: {src} connected to {len(dsts)} hosts (possible IPC$/share traversal)',
                    mitre='T1021.002', source=src,
                    extra={'src_ip': src, 'attack_name': 'SMB Tree/IPC$ Abuse', 'target_count': len(dsts)})

    def _detect_remote_service_creation(self):
        """NABD-48: Remote Service/Scheduled Task Creation. T1543.003"""
        # RPC on 135 followed by ephemeral port SMB/WMI = remote service creation
        rpc_src = set()
        for fk in self.flows:
            if len(fk) == 5 and fk[3] == 135:
                rpc_src.add(fk[0])
        svc_create = set()
        for fk in self.flows:
            if len(fk) == 5 and fk[0] in rpc_src and fk[3] in (445, 49152, 49153, 49154, 49155):
                svc_create.add(fk[0])
        for src in svc_create:
            self._add_anomaly('critical', 'LATERAL_MOVEMENT', 'NABD-48',
                f'Remote service creation: {src} — RPC/135 + ephemeral SMB (svc/task creation pattern)',
                mitre='T1543.003', source=src,
                extra={'src_ip': src, 'attack_name': 'Remote Service/Task Creation'})

    def _detect_internal_scan(self):
        """NABD-49: Internal Network Scanning (east-west discovery). T1046"""
        # Internal IP scanning other internal IPs on many ports
        internal_scanners = defaultdict(set)
        for fk in self.flows:
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if _is_private(src) and _is_private(dst) and src != dst:
                    internal_scanners[src].add(dp)
        for src, ports in internal_scanners.items():
            if len(ports) > 25:
                self._add_anomaly('critical', 'LATERAL_MOVEMENT', 'NABD-49',
                    f'Internal east-west scan: {src} probed {len(ports)} unique ports on internal hosts',
                    mitre='T1046', source=src,
                    extra={'src_ip': src, 'attack_name': 'Internal Network Scan', 'port_count': len(ports)})

    def _detect_chunked_exfil(self):
        """NABD-50: Chunked Data Exfiltration (many small uploads). T1048"""
        # Many small POSTs to same external host = chunked exfil
        post_count  = defaultdict(int)
        post_bytes  = defaultdict(int)
        for req in self.http_requests:
            if req.get('method') == 'POST':
                dst = req.get('host', '') or req.get('dst_ip', '')
                if dst and not _is_private(req.get('dst_ip', '127.0.0.1')):
                    post_count[dst] += 1
                    post_bytes[dst] += req.get('payload_len', 0)
        for dst, count in post_count.items():
            if count > 10 and post_bytes[dst] > 10000:
                self._add_anomaly('high', 'EXFILTRATION', 'NABD-50',
                    f'Chunked exfil: {count} HTTP POSTs to {dst} totaling {_human_bytes(post_bytes[dst])} (time-spread uploads)',
                    mitre='T1048',
                    extra={'dst_ip': dst, 'attack_name': 'Chunked HTTP Exfiltration',
                           'upload_count': count, 'total_bytes': post_bytes[dst]})
                self.iocs.append({'type': 'exfil_endpoint', 'value': dst})

    def _detect_protocol_masquerade(self):
        """NABD-52: Protocol Masquerading (HTTP on non-80, DNS on non-53). T1571"""
        # HTTP-like traffic on non-standard ports
        for pkt in self.all_packets:
            tcp = pkt.get('tcp')
            if not tcp: continue
            dp = tcp.get('dst_port', 0)
            payload = tcp.get('payload', b'')
            if not payload: continue
            # HTTP on non-standard port
            if dp not in (80, 8080, 8000, 8443, 443, 3000, 5000) and dp > 1024:
                if payload[:4] in (b'GET ', b'POST', b'HTTP', b'HEAD', b'PUT '):
                    ip = pkt.get('ip', {})
                    src = ip.get('src_ip', '')
                    self._add_anomaly('medium', 'PROTOCOL_ANOMALY', 'NABD-52',
                        f'Protocol masquerade: HTTP on port {dp} from {src} (non-standard port)',
                        mitre='T1571', source=src,
                        extra={'src_ip': src, 'dst_port': dp, 'attack_name': 'Protocol Masquerade'})
                    break
            # DNS on non-53 port
            if dp not in (53, 5353) and len(payload) > 12:
                # DNS header: 2B ID, 2B flags, 4x 2B counts
                flags_byte = payload[2] if len(payload) > 3 else 0
                if (flags_byte & 0xf8) in (0x00, 0x80) and len(payload) < 512:
                    ip = pkt.get('ip', {})
                    src = ip.get('src_ip', '')
                    if src:
                        self._add_anomaly('medium', 'PROTOCOL_ANOMALY', 'NABD-52',
                            f'Protocol masquerade: DNS-like traffic on port {dp} from {src}',
                            mitre='T1571', source=src,
                            extra={'src_ip': src, 'dst_port': dp, 'attack_name': 'DNS Masquerade'})
                        break

    def _detect_internal_exfil(self):
        """NABD-53: Internal-to-Internal Lateral Exfiltration. T1074"""
        # Large transfer between internal hosts (staging before external exfil)
        for fk, fv in self.flows.items():
            if len(fk) != 5: continue
            src, dst, sp, dp, proto = fk
            if _is_private(src) and _is_private(dst) and fv['bytes'] > 5_000_000:
                self._add_anomaly('high', 'EXFILTRATION', 'NABD-53',
                    f'Internal staging exfil: {src} -> {dst} transferred {_human_bytes(fv["bytes"])} (east-west large transfer)',
                    mitre='T1074', source=src, destination=dst,
                    extra={'src_ip': src, 'dst_ip': dst, 'attack_name': 'Internal Staging Exfil',
                           'bytes': fv['bytes']})
                self.iocs.append({'type': 'staging_host', 'value': dst})

    def _detect_beacon_interval_analysis(self):
        """NABD-54: Precise Beacon Interval / Inter-Arrival Time Analysis. T1071"""
        # Enhanced beaconing: analyze inter-arrival times per dst IP
        dst_times = defaultdict(list)
        for fk, fv in self.flows.items():
            if len(fk) == 5:
                src, dst, sp, dp, proto = fk
                if not _is_private(dst):
                    dst_times[(src, dst, dp)].append(fv['start'])
        for (src, dst, dp), times in dst_times.items():
            if len(times) < 5: continue
            times_s = sorted(times)
            intervals = [times_s[i+1] - times_s[i] for i in range(len(times_s)-1)]
            if not intervals: continue
            mean_iv = sum(intervals) / len(intervals)
            if mean_iv < 1: continue
            std_iv = (sum((x - mean_iv)**2 for x in intervals) / len(intervals)) ** 0.5
            cv = std_iv / mean_iv  # Coefficient of variation
            if cv < 0.15 and len(times) >= 6:  # Very regular = automated beaconing
                self._add_anomaly('critical', 'C2_BEACONING', 'NABD-54',
                    f'Precise beacon IAT: {src} -> {dst}:{dp} — interval={mean_iv:.1f}s, CV={cv:.3f} (highly regular = malware)',
                    mitre='T1071', source=src, destination=dst,
                    extra={'src_ip': src, 'dst_ip': dst, 'dst_port': dp,
                           'attack_name': 'Precise C2 Beacon (IAT)',
                           'beacon_interval': mean_iv, 'cv': cv, 'connection_count': len(times)})
                self.iocs.append({'type': 'c2_server', 'value': f'{dst}:{dp}'})

    def _detect_payload_entropy_analysis(self):
        """NABD-55: High-Entropy Payload Detection (encrypted/packed content). T1027"""
        high_entropy_flows = defaultdict(float)
        high_entropy_srcs  = defaultdict(str)
        for pkt in self.all_packets:
            for layer in ('tcp', 'udp'):
                l = pkt.get(layer)
                if not l: continue
                payload = l.get('payload', b'')
                if len(payload) < 64: continue
                try:
                    text = payload.decode('latin-1')
                except Exception:
                    text = payload.decode('utf-8', errors='replace')
                ent = _entropy(text)
                if ent > 7.2:  # Near-maximum entropy = encryption/packing
                    ip = pkt.get('ip', {})
                    src = ip.get('src_ip', '')
                    dst = ip.get('dst_ip', '')
                    dp  = l.get('dst_port', 0)
                    key = (src, dst, dp)
                    if ent > high_entropy_flows.get(key, 0):
                        high_entropy_flows[key] = ent
                        high_entropy_srcs[key] = f'{src} -> {dst}:{dp}'
        for key, ent in list(high_entropy_flows.items())[:5]:
            src, dst, dp = key
            if not _is_private(dst):
                self._add_anomaly('medium', 'EXFILTRATION', 'NABD-55',
                    f'High-entropy payload (entropy={ent:.2f}): {src} -> {dst}:{dp} — encrypted/packed data, possible exfil',
                    mitre='T1027', source=src, destination=dst,
                    extra={'src_ip': src, 'dst_ip': dst, 'dst_port': dp,
                           'attack_name': 'High-Entropy Encrypted Payload', 'entropy': ent})

    # Process wrapper — add new detections to the detection pipeline
    def _run_nabd_docx_detections(self):
        """Run all new detections from the NABD input document."""
        self._detect_tcp_connect_scan()
        self._detect_tcp_ack_scan()
        self._detect_slow_service_enum()
        self._detect_web_dir_bruteforce()
        self._detect_low_slow_password_spray()
        self._detect_ntlm_downgrade()
        self._detect_buffer_overflow()
        self._detect_exploit_kit_traffic()
        self._detect_malicious_payload_download()
        self._detect_http_smuggling()
        self._detect_fileless_exploitation()
        self._detect_tls_cert_abuse()
        self._detect_http_header_covert()
        self._detect_doh_dot_abuse()
        self._detect_smb_tree_abuse()
        self._detect_remote_service_creation()
        self._detect_internal_scan()
        self._detect_chunked_exfil()
        self._detect_protocol_masquerade()
        self._detect_internal_exfil()
        self._detect_beacon_interval_analysis()
        self._detect_payload_entropy_analysis()

    # ══════════════════════════════════════════════════════════════════════════
    # RESULTS COMPILER
    # ══════════════════════════════════════════════════════════════════════════

    def _compile_results(self):
        """Compile all analysis into final results dict."""
        duration = (max(self.timestamps) - min(self.timestamps)) if len(self.timestamps) >= 2 else 0
        pps = self.total_packets / duration if duration > 0 else 0
        bps = self.total_bytes / duration if duration > 0 else 0

        top_src = Counter()
        top_dst = Counter()
        for (src, dst), count in self.src_dst_pairs.items():
            top_src[src] += count
            top_dst[dst] += count

        top_flows = sorted(self.flows.items(), key=lambda x: x[1]['bytes'], reverse=True)[:20]

        score = 0
        for a in self.anomalies:
            if a['severity'] == 'critical': score += 25
            elif a['severity'] == 'high': score += 15
            elif a['severity'] == 'medium': score += 8
            elif a['severity'] == 'low': score += 3
        score = min(score, 100)

        if score >= 50: risk_level = 'CRITICAL'
        elif score >= 30: risk_level = 'HIGH'
        elif score >= 15: risk_level = 'MEDIUM'
        elif score > 0: risk_level = 'LOW'
        else: risk_level = 'CLEAN'

        # Extract IOCs
        for ip in self.external_ips:
            self.iocs.append({'type': 'external_ip', 'value': ip})
        for q in self.dns_queries:
            name = q.get('name', '')
            if name and not name.endswith('.local') and not name.endswith('.arpa'):
                self.iocs.append({'type': 'domain', 'value': name})
        for req in self.http_requests:
            host = req.get('host', '')
            uri = req.get('uri', '')
            if host: self.iocs.append({'type': 'url', 'value': f'http://{host}{uri}'})
        for hs in self.tls_handshakes:
            if hs.get('sni'): self.iocs.append({'type': 'tls_sni', 'value': hs['sni']})

        # Deduplicate IOCs
        seen = set()
        unique_iocs = []
        for ioc in self.iocs:
            k = f"{ioc['type']}:{ioc['value']}"
            if k not in seen:
                seen.add(k); unique_iocs.append(ioc)

        unique_domains = sorted(set(q.get('name', '') for q in self.dns_queries if q.get('name')))

        # Group anomalies by category
        anomaly_summary = Counter(a.get('category', 'UNKNOWN') for a in self.anomalies)

        return {
            'summary': {
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'total_bytes_human': _human_bytes(self.total_bytes),
                'duration_seconds': round(duration, 2),
                'duration_human': str(timedelta(seconds=int(duration))) if duration else '0:00:00',
                'packets_per_second': round(pps, 1),
                'bytes_per_second': round(bps, 1),
                'bandwidth_human': f'{_human_bytes(bps)}/s',
                'unique_ips': len(self.unique_ips),
                'unique_macs': len(self.unique_macs),
                'external_ips': len(self.external_ips),
                'internal_ips': len(self.internal_ips),
                'total_flows': len(self.flows),
                'first_timestamp': min(self.timestamps) if self.timestamps else 0,
                'last_timestamp': max(self.timestamps) if self.timestamps else 0,
            },
            'protocols': dict(self.protocol_counter.most_common()),
            'top_talkers_src': dict(top_src.most_common(15)),
            'top_talkers_dst': dict(top_dst.most_common(15)),
            'top_ports': dict(self.port_counter.most_common(20)),
            'top_flows': [{
                'key': f'{k[0]}:{k[2]} <-> {k[1]}:{k[3]} ({k[4]})' if len(k) == 5 else str(k),
                'src_ip':   k[0] if len(k) == 5 else '',
                'src_port': k[2] if len(k) == 5 else 0,
                'dst_ip':   k[1] if len(k) == 5 else '',
                'dst_port': k[3] if len(k) == 5 else 0,
                'proto':    k[4] if len(k) == 5 else '',
                'packets': v['packets'], 'bytes': v['bytes'],
                'bytes_human': _human_bytes(v['bytes']),
                'duration': round(v['end'] - v['start'], 2) if v['end'] > v['start'] else 0,
                'direction': ('Int→Int' if (_is_private(k[0]) and _is_private(k[1])) else
                              'Int→Ext' if _is_private(k[0]) else
                              'Ext→Int' if _is_private(k[1]) else 'Ext→Ext') if len(k)==5 else '',
            } for k, v in top_flows],
            'dns': {
                'total_queries': len(self.dns_queries),
                'unique_domains': len(unique_domains),
                'top_domains': dict(Counter(q.get('name','') for q in self.dns_queries).most_common(20)),
                'query_types': dict(Counter(q.get('type','') for q in self.dns_queries).most_common()),
                'domains': unique_domains[:100],
            },
            'http': {
                'total_requests': len(self.http_requests),
                'methods': dict(Counter(r.get('method','') for r in self.http_requests).most_common()),
                'hosts': dict(Counter(r.get('host','') for r in self.http_requests).most_common(20)),
                'user_agents': dict(self.user_agents.most_common(10)),
                'requests': self.http_requests[:50],
            },
            'tls': {
                'total_handshakes': len(self.tls_handshakes),
                'versions': dict(Counter(h.get('version','') for h in self.tls_handshakes).most_common()),
                'sni_list': sorted(set(h.get('sni','') for h in self.tls_handshakes if h.get('sni'))),
                'deprecated_count': sum(1 for h in self.tls_handshakes if h.get('deprecated')),
            },
            'anomalies': self.anomalies,
            'anomaly_summary': dict(anomaly_summary),
            'threat_score': score,
            'risk_level': risk_level,
            'iocs': unique_iocs,
            'ttl_distribution': dict(self.ttl_values.most_common(10)),
        }
class DemoGenerator:
    """Generates a sample PCAP file with various traffic patterns for testing."""

    @staticmethod
    def generate(output_path: str):
        """Generate a realistic demo PCAP file."""
        packets = []
        base_time = int(time.time()) - 300  # 5 minutes ago

        def make_eth(src_mac, dst_mac, ethertype=0x0800):
            return (bytes.fromhex(dst_mac.replace(':','')) +
                    bytes.fromhex(src_mac.replace(':','')) +
                    struct.pack('!H', ethertype))

        def make_ipv4(src, dst, proto, payload_len, ttl=64, ident=0):
            total_len = 20 + payload_len
            header = struct.pack('!BBHHHBBH4s4s',
                0x45, 0, total_len, ident, 0x4000, ttl, proto, 0,
                socket.inet_aton(src), socket.inet_aton(dst))
            return header

        def make_tcp(sp, dp, seq=1000, ack=0, flags=0x02, payload=b''):
            offset = 5
            off_flags = (offset << 12) | flags
            header = struct.pack('!HHIIHHHH', sp, dp, seq, ack, off_flags, 65535, 0, 0)
            return header + payload

        def make_udp(sp, dp, payload=b''):
            length = 8 + len(payload)
            return struct.pack('!HHHH', sp, dp, length, 0) + payload

        def make_dns_query(domain, txn_id=0x1234, qtype=1):
            header = struct.pack('!HHHHHH', txn_id, 0x0100, 1, 0, 0, 0)
            qname = b''
            for label in domain.split('.'):
                qname += struct.pack('B', len(label)) + label.encode()
            qname += b'\x00'
            question = qname + struct.pack('!HH', qtype, 1)
            return header + question

        def add_packet(data, ts_offset):
            packets.append((base_time + ts_offset, data))

        local_mac = 'aa:bb:cc:dd:ee:01'
        gw_mac = 'aa:bb:cc:dd:ee:ff'
        local_ip = '192.168.1.100'
        gw_ip = '192.168.1.1'

        # Normal DNS queries
        for i, domain in enumerate(['google.com', 'github.com', 'example.com', 'api.stripe.com',
                                      'cdn.cloudflare.com', 'fonts.googleapis.com']):
            dns = make_dns_query(domain, txn_id=0x1000 + i)
            udp = make_udp(50000 + i, 53, dns)
            ip = make_ipv4(local_ip, '8.8.8.8', 17, len(udp))
            eth = make_eth(local_mac, gw_mac)
            add_packet(eth + ip + udp, i * 2)

        # Normal HTTPS (TLS ClientHello with SNI)
        for i, (sni, dst_ip) in enumerate([
            ('www.google.com', '142.250.80.100'), ('github.com', '20.27.177.113'),
            ('api.stripe.com', '104.18.10.39'),
        ]):
            sni_ext = struct.pack('!HH', 0, len(sni) + 5) + struct.pack('!HBH', len(sni) + 3, 0, len(sni)) + sni.encode()
            extensions = sni_ext
            ext_block = struct.pack('!H', len(extensions)) + extensions
            cipher_suites = struct.pack('!H', 4) + struct.pack('!HH', 0x1301, 0x1302)
            session_id = b'\x00'
            client_hello = struct.pack('!HH32s', 0x0303, 0, b'\x00'*32) + session_id + cipher_suites + b'\x01\x00' + ext_block
            hs_header = struct.pack('!B', 1) + struct.pack('!I', len(client_hello))[1:]
            tls_record = struct.pack('!BHH', 0x16, 0x0301, len(hs_header + client_hello)) + hs_header + client_hello
            tcp = make_tcp(50100 + i, 443, flags=0x18, payload=tls_record)
            ip_pkt = make_ipv4(local_ip, dst_ip, 6, len(tcp))
            eth = make_eth(local_mac, gw_mac)
            add_packet(eth + ip_pkt + tcp, 15 + i * 3)

        # HTTP requests (cleartext)
        for i, (host, uri) in enumerate([
            ('example.com', '/api/data'), ('internal-app.local', '/login'),
            ('tracking.ads.net', '/pixel?uid=12345'),
        ]):
            http_payload = f'GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\n\r\n'.encode()
            tcp = make_tcp(50200 + i, 80, flags=0x18, payload=http_payload)
            ip_pkt = make_ipv4(local_ip, '93.184.216.34', 6, len(tcp))
            eth = make_eth(local_mac, gw_mac)
            add_packet(eth + ip_pkt + tcp, 30 + i * 5)

        # Suspicious: beaconing pattern (every ~60s to same IP)
        c2_ip = '185.220.101.42'
        for i in range(5):
            tcp = make_tcp(49000, 4444, seq=1000 + i * 100, flags=0x18, payload=b'\x00' * 64)
            ip_pkt = make_ipv4(local_ip, c2_ip, 6, len(tcp))
            eth = make_eth(local_mac, gw_mac)
            add_packet(eth + ip_pkt + tcp, 60 + i * 60)

        # DNS tunneling pattern
        for i in range(15):
            long_sub = hashlib.md5(f'exfil-data-chunk-{i}'.encode()).hexdigest()
            tunnel_domain = f'{long_sub}.tunnel.evil-domain.com'
            dns = make_dns_query(tunnel_domain, txn_id=0x2000 + i, qtype=16)
            udp = make_udp(51000 + i, 53, dns)
            ip_pkt = make_ipv4(local_ip, '8.8.8.8', 17, len(udp))
            eth = make_eth(local_mac, gw_mac)
            add_packet(eth + ip_pkt + udp, 50 + i * 3)

        # ARP requests/replies (normal)
        arp_req = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)
        arp_req += bytes.fromhex(local_mac.replace(':','')) + socket.inet_aton(local_ip)
        arp_req += b'\x00' * 6 + socket.inet_aton(gw_ip)
        eth = make_eth(local_mac, 'ff:ff:ff:ff:ff:ff', 0x0806)
        add_packet(eth + arp_req, 1)

        # ARP spoofing attempt (different MAC for same IP)
        spoof_mac = 'de:ad:be:ef:00:01'
        arp_spoof = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2)
        arp_spoof += bytes.fromhex(spoof_mac.replace(':','')) + socket.inet_aton(gw_ip)
        arp_spoof += bytes.fromhex(local_mac.replace(':','')) + socket.inet_aton(local_ip)
        eth = make_eth(spoof_mac, local_mac, 0x0806)
        add_packet(eth + arp_spoof, 100)

        # ICMP ping
        icmp = struct.pack('!BBHI', 8, 0, 0, 0x0001_0001) + b'ABCDEFGH'
        ip_pkt = make_ipv4(local_ip, '8.8.8.8', 1, len(icmp))
        eth = make_eth(local_mac, gw_mac)
        add_packet(eth + ip_pkt + icmp, 5)

        # Deprecated TLS (SSL 3.0)
        old_tls = struct.pack('!BHH', 0x16, 0x0300, 5) + struct.pack('!B', 1) + b'\x00\x00\x01\x00'
        tcp = make_tcp(50300, 443, flags=0x18, payload=old_tls)
        ip_pkt = make_ipv4(local_ip, '10.0.0.50', 6, len(tcp))
        eth = make_eth(local_mac, gw_mac)
        add_packet(eth + ip_pkt + tcp, 200)

        # Write PCAP
        packets.sort(key=lambda x: x[0])
        with open(output_path, 'wb') as f:
            # Global header
            f.write(struct.pack('<IHHiIII', PCAP_MAGIC_LE, 2, 4, 0, 0, 65535, 1))
            for ts, data in packets:
                ts_sec = int(ts)
                ts_usec = int((ts - ts_sec) * 1e6)
                f.write(struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)))
                f.write(data)

        return output_path


# ═══════════════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """
    HFL Passive Threat Hunting Report Generator v4.0
    Light-theme, multi-section HTML report with full MITRE ATT&CK sub-technique
    details, hyperlinked HACKFORLAB brand, tabular anomaly display, charts.
    """

    # ── Full MITRE ATT&CK reference catalogue ─────────────────────────────────
    MITRE_DB = {
        # Reconnaissance
        'T1046':   {'name':'Network Service Discovery','tactic':'Reconnaissance','url':'https://attack.mitre.org/techniques/T1046/','desc':'Adversaries may scan for open ports and services on remote hosts.'},
        'T1592':   {'name':'Gather Victim Host Information','tactic':'Reconnaissance','url':'https://attack.mitre.org/techniques/T1592/','desc':'Adversaries may gather info about the victim\'s hosts before compromising.'},
        'T1590':   {'name':'Gather Victim Network Information','tactic':'Reconnaissance','url':'https://attack.mitre.org/techniques/T1590/','desc':'Adversaries gather info about the target network infrastructure.'},
        'T1135':   {'name':'Network Share Discovery','tactic':'Discovery','url':'https://attack.mitre.org/techniques/T1135/','desc':'Adversaries may look for folders and drives shared on remote systems.'},
        'T1087':   {'name':'Account Discovery','tactic':'Discovery','url':'https://attack.mitre.org/techniques/T1087/','desc':'Adversaries may attempt to get a listing of valid accounts on a network.'},
        'T1083':   {'name':'File and Directory Discovery','tactic':'Discovery','url':'https://attack.mitre.org/techniques/T1083/','desc':'Adversaries may enumerate files and directories on a compromised system.'},
        # C2
        'T1071':   {'name':'Application Layer Protocol','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1071/','desc':'Adversaries may communicate via application layer protocols to avoid detection.'},
        'T1071.001':{'name':'Application Layer Protocol: Web Protocols','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1071/001/','desc':'Adversaries may use HTTP/HTTPS for C2 communications.'},
        'T1071.003':{'name':'Application Layer Protocol: Mail Protocols','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1071/003/','desc':'Adversaries may use mail protocols (IRC) for C2 communications.'},
        'T1071.004':{'name':'Application Layer Protocol: DNS','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1071/004/','desc':'Adversaries may use DNS for C2 communications.'},
        'T1095':   {'name':'Non-Application Layer Protocol','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1095/','desc':'Adversaries may use non-application layer protocols such as ICMP for C2.'},
        'T1568':   {'name':'Dynamic Resolution','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1568/','desc':'Adversaries may dynamically establish connections to C2 infrastructure.'},
        'T1568.001':{'name':'Dynamic Resolution: Fast Flux DNS','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1568/001/','desc':'Adversaries use fast flux DNS to hide C2 infrastructure.'},
        'T1568.002':{'name':'Dynamic Resolution: Domain Generation Algorithms','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1568/002/','desc':'Adversaries may use DGA to procedurally generate domain names for C2.'},
        'T1090':   {'name':'Proxy','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1090/','desc':'Adversaries may use proxy servers to obscure C2 traffic.'},
        'T1090.003':{'name':'Proxy: Multi-hop Proxy','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1090/003/','desc':'Adversaries may chain proxies (e.g. Tor) to disguise origin.'},
        'T1090.004':{'name':'Proxy: Domain Fronting','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1090/004/','desc':'Adversaries may use domain fronting to disguise C2 traffic via CDN.'},
        'T1219':   {'name':'Remote Access Software','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1219/','desc':'Adversaries may use RAT software to maintain access to compromised hosts.'},
        'T1572':   {'name':'Protocol Tunneling','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1572/','desc':'Adversaries may tunnel data within application/network protocols.'},
        'T1571':   {'name':'Non-Standard Port','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1571/','desc':'Adversaries may communicate over a non-standard port to bypass security.'},
        'T1573':   {'name':'Encrypted Channel','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1573/','desc':'Adversaries may employ an encrypted channel to hide communications.'},
        'T1027':   {'name':'Obfuscated Files or Information','tactic':'Defense Evasion','url':'https://attack.mitre.org/techniques/T1027/','desc':'Adversaries may obfuscate content to make it difficult to discover or analyze.'},
        # Exfiltration
        'T1041':   {'name':'Exfiltration Over C2 Channel','tactic':'Exfiltration','url':'https://attack.mitre.org/techniques/T1041/','desc':'Adversaries may steal data by exfiltrating it over the C2 channel.'},
        'T1048':   {'name':'Exfiltration Over Alternative Protocol','tactic':'Exfiltration','url':'https://attack.mitre.org/techniques/T1048/','desc':'Adversaries may steal data by exfiltrating it over a different protocol.'},
        'T1048.001':{'name':'Exfiltration Over Alternative Protocol: Exfil Over Symmetric Encrypted Non-C2 Protocol','tactic':'Exfiltration','url':'https://attack.mitre.org/techniques/T1048/001/','desc':'Adversaries may steal data via encrypted alternative protocols.'},
        'T1048.002':{'name':'Exfiltration Over Alternative Protocol: Exfil Over Asymmetric Encrypted Non-C2 Protocol','tactic':'Exfiltration','url':'https://attack.mitre.org/techniques/T1048/002/','desc':'Adversaries steal data via SMTP or other asymmetric protocols.'},
        'T1048.003':{'name':'Exfiltration Over Alternative Protocol: Exfil Over Unencrypted Non-C2 Protocol','tactic':'Exfiltration','url':'https://attack.mitre.org/techniques/T1048/003/','desc':'Adversaries steal data via FTP, DNS, or other unencrypted protocols.'},
        'T1567':   {'name':'Exfiltration Over Web Service','tactic':'Exfiltration','url':'https://attack.mitre.org/techniques/T1567/','desc':'Adversaries may use an existing, legitimate external web service to exfiltrate data.'},
        'T1074':   {'name':'Data Staged','tactic':'Collection','url':'https://attack.mitre.org/techniques/T1074/','desc':'Adversaries may stage collected data in a central location prior to exfiltration.'},
        # Impact
        'T1498':   {'name':'Network Denial of Service','tactic':'Impact','url':'https://attack.mitre.org/techniques/T1498/','desc':'Adversaries may perform DoS attacks to degrade availability.'},
        'T1498.001':{'name':'Network DoS: Direct Network Flood','tactic':'Impact','url':'https://attack.mitre.org/techniques/T1498/001/','desc':'Adversaries may flood network bandwidth using high-volume packet flood.'},
        'T1498.002':{'name':'Network DoS: Reflection Amplification','tactic':'Impact','url':'https://attack.mitre.org/techniques/T1498/002/','desc':'Adversaries may amplify attack traffic using reflection.'},
        'T1499':   {'name':'Endpoint Denial of Service','tactic':'Impact','url':'https://attack.mitre.org/techniques/T1499/','desc':'Adversaries may perform DoS attacks on endpoints.'},
        'T1486':   {'name':'Data Encrypted for Impact','tactic':'Impact','url':'https://attack.mitre.org/techniques/T1486/','desc':'Adversaries may encrypt data on target systems (ransomware).'},
        # Lateral Movement
        'T1021':   {'name':'Remote Services','tactic':'Lateral Movement','url':'https://attack.mitre.org/techniques/T1021/','desc':'Adversaries may use valid accounts to log into remote services.'},
        'T1021.001':{'name':'Remote Services: Remote Desktop Protocol','tactic':'Lateral Movement','url':'https://attack.mitre.org/techniques/T1021/001/','desc':'Adversaries may use RDP to log into remote systems.'},
        'T1021.002':{'name':'Remote Services: SMB/Windows Admin Shares','tactic':'Lateral Movement','url':'https://attack.mitre.org/techniques/T1021/002/','desc':'Adversaries may use SMB shares to move laterally.'},
        'T1021.003':{'name':'Remote Services: Distributed Component Object Model','tactic':'Lateral Movement','url':'https://attack.mitre.org/techniques/T1021/003/','desc':'Adversaries may use DCOM for lateral movement.'},
        'T1021.004':{'name':'Remote Services: SSH','tactic':'Lateral Movement','url':'https://attack.mitre.org/techniques/T1021/004/','desc':'Adversaries may use SSH to log into remote systems.'},
        'T1021.006':{'name':'Remote Services: Windows Remote Management','tactic':'Lateral Movement','url':'https://attack.mitre.org/techniques/T1021/006/','desc':'Adversaries may use WinRM for lateral movement.'},
        'T1570':   {'name':'Lateral Tool Transfer','tactic':'Lateral Movement','url':'https://attack.mitre.org/techniques/T1570/','desc':'Adversaries may transfer tools or files between systems in an environment.'},
        'T1550':   {'name':'Use Alternate Authentication Material','tactic':'Lateral Movement','url':'https://attack.mitre.org/techniques/T1550/','desc':'Adversaries may use alternate authentication material to move laterally.'},
        'T1550.002':{'name':'Use Alternate Auth: Pass the Hash','tactic':'Lateral Movement','url':'https://attack.mitre.org/techniques/T1550/002/','desc':'Adversaries may pass the hash to authenticate without a plaintext password.'},
        'T1543.003':{'name':'Create or Modify System Process: Windows Service','tactic':'Persistence','url':'https://attack.mitre.org/techniques/T1543/003/','desc':'Adversaries may create or modify Windows services for persistence.'},
        # Credential Access
        'T1557':   {'name':'Adversary-in-the-Middle','tactic':'Credential Access','url':'https://attack.mitre.org/techniques/T1557/','desc':'Adversaries may position themselves between communications to steal credentials.'},
        'T1557.001':{'name':'AiTM: LLMNR/NBT-NS Poisoning and SMB Relay','tactic':'Credential Access','url':'https://attack.mitre.org/techniques/T1557/001/','desc':'Adversaries may poison LLMNR/NBT-NS/mDNS and relay SMB/NTLM credentials.'},
        'T1557.002':{'name':'AiTM: ARP Cache Poisoning','tactic':'Credential Access','url':'https://attack.mitre.org/techniques/T1557/002/','desc':'Adversaries may poison ARP caches to intercept traffic.'},
        'T1558':   {'name':'Steal or Forge Kerberos Tickets','tactic':'Credential Access','url':'https://attack.mitre.org/techniques/T1558/','desc':'Adversaries may attempt to steal Kerberos tickets.'},
        'T1558.003':{'name':'Kerberos: Kerberoasting','tactic':'Credential Access','url':'https://attack.mitre.org/techniques/T1558/003/','desc':'Adversaries may abuse Kerberos tickets to obtain service account passwords.'},
        'T1558.004':{'name':'Kerberos: AS-REP Roasting','tactic':'Credential Access','url':'https://attack.mitre.org/techniques/T1558/004/','desc':'Adversaries may reveal credentials without pre-auth requirement.'},
        'T1110':   {'name':'Brute Force','tactic':'Credential Access','url':'https://attack.mitre.org/techniques/T1110/','desc':'Adversaries may use brute force techniques to gain access.'},
        'T1110.001':{'name':'Brute Force: Password Guessing','tactic':'Credential Access','url':'https://attack.mitre.org/techniques/T1110/001/','desc':'Adversaries may try many passwords against an account.'},
        'T1110.003':{'name':'Brute Force: Password Spraying','tactic':'Credential Access','url':'https://attack.mitre.org/techniques/T1110/003/','desc':'Adversaries use a single password against many accounts.'},
        'T1078':   {'name':'Valid Accounts','tactic':'Defense Evasion','url':'https://attack.mitre.org/techniques/T1078/','desc':'Adversaries may obtain valid accounts to maintain access.'},
        'T1078.001':{'name':'Valid Accounts: Default Accounts','tactic':'Defense Evasion','url':'https://attack.mitre.org/techniques/T1078/001/','desc':'Adversaries may use default accounts left on systems.'},
        # Exploitation
        'T1190':   {'name':'Exploit Public-Facing Application','tactic':'Initial Access','url':'https://attack.mitre.org/techniques/T1190/','desc':'Adversaries may exploit weakness in internet-facing software.'},
        'T1189':   {'name':'Drive-by Compromise','tactic':'Initial Access','url':'https://attack.mitre.org/techniques/T1189/','desc':'Adversaries may gain access through user visiting a malicious website.'},
        'T1105':   {'name':'Ingress Tool Transfer','tactic':'Command and Control','url':'https://attack.mitre.org/techniques/T1105/','desc':'Adversaries may transfer tools or files from external system.'},
        'T1210':   {'name':'Exploitation of Remote Services','tactic':'Lateral Movement','url':'https://attack.mitre.org/techniques/T1210/','desc':'Adversaries may exploit remote services to gain access within a network.'},
        'T1059':   {'name':'Command and Scripting Interpreter','tactic':'Execution','url':'https://attack.mitre.org/techniques/T1059/','desc':'Adversaries abuse command-line interfaces or scripting to execute commands.'},
        'T1059.001':{'name':'Scripting: PowerShell','tactic':'Execution','url':'https://attack.mitre.org/techniques/T1059/001/','desc':'Adversaries may abuse PowerShell to execute commands.'},
        # Defense Evasion
        'T1040':   {'name':'Network Sniffing','tactic':'Credential Access','url':'https://attack.mitre.org/techniques/T1040/','desc':'Adversaries may sniff network traffic to capture credentials.'},
        'T1600':   {'name':'Weaken Encryption','tactic':'Defense Evasion','url':'https://attack.mitre.org/techniques/T1600/','desc':'Adversaries may compromise encryption to expose encrypted communications.'},
        # Other
        'T1014':   {'name':'Rootkit','tactic':'Defense Evasion','url':'https://attack.mitre.org/techniques/T1014/','desc':'Adversaries may use rootkits to hide the presence of malicious programs.'},
        'T1018':   {'name':'Remote System Discovery','tactic':'Discovery','url':'https://attack.mitre.org/techniques/T1018/','desc':'Adversaries may attempt to get a listing of other systems by IP address.'},
        'T1566':   {'name':'Phishing','tactic':'Initial Access','url':'https://attack.mitre.org/techniques/T1566/','desc':'Adversaries may send phishing messages to gain access.'},
    }

    @staticmethod
    def _mitre_info(tid):
        """Return MITRE info dict for a technique ID, falling back to base technique."""
        db = ReportGenerator.MITRE_DB
        if tid in db:
            return db[tid]
        base = tid.split('.')[0] if '.' in tid else tid
        if base in db:
            d = dict(db[base])
            d['name'] = d['name'] + f' ({tid})'
            return d
        return {'name': tid, 'tactic': 'Unknown', 'url': f'https://attack.mitre.org/techniques/{tid.replace(".","/")}/','desc':''}

    @staticmethod
    def generate(analysis, file_info, output_path):
        import json as _json
        ts   = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        rid  = hashlib.sha256(f'{ts}{id(analysis)}'.encode()).hexdigest()[:12].upper()
        s    = analysis.get('summary', {})
        risk = analysis.get('risk_level', 'CLEAN')
        score= analysis.get('threat_score', 0)
        anomalies = analysis.get('anomalies', [])

        def e(v):
            return _esc(str(v)) if v is not None else ''

        # ── colour scheme (light) ────────────────────────────────────────────
        RISK_BORDER = {
            'CLEAN':  '#16a34a','LOW': '#ca8a04','MEDIUM':'#ea580c',
            'HIGH':   '#dc2626','CRITICAL':'#991b1b',
        }
        risk_color = RISK_BORDER.get(risk, '#64748b')

        SC = '#16a34a' if score < 15 else '#ca8a04' if score < 30 else '#ea580c' if score < 50 else '#dc2626'

        # ── severity counts ───────────────────────────────────────────────────
        sev = {'critical':0,'high':0,'medium':0,'low':0,'info':0}
        for a in anomalies:
            k = a.get('severity','info')
            sev[k] = sev.get(k,0) + 1

        # ── category breakdown ────────────────────────────────────────────────
        cat_counts = {}
        for a in anomalies:
            c = a.get('category','OTHER')
            cat_counts[c] = cat_counts.get(c,0)+1

        # ── MITRE breakdown (with tactic grouping) ────────────────────────────
        mitre_seen = {}
        tactic_counts = {}
        for a in anomalies:
            m = a.get('mitre','')
            if m:
                mitre_seen[m] = mitre_seen.get(m,0)+1
                info = ReportGenerator._mitre_info(m)
                t = info.get('tactic','Unknown')
                tactic_counts[t] = tactic_counts.get(t,0)+1

        # ── top_flows ─────────────────────────────────────────────────────────
        top_flows = analysis.get('top_flows', [])

        # ── Chart.js data ─────────────────────────────────────────────────────
        sev_labels = _json.dumps(list(sev.keys()))
        sev_data   = _json.dumps(list(sev.values()))
        sev_colors = _json.dumps(['#dc2626','#ef4444','#f97316','#eab308','#3b82f6'])

        cat_sorted = sorted(cat_counts.items(), key=lambda x:-x[1])[:12]
        cat_labels = _json.dumps([c[0] for c in cat_sorted])
        cat_data   = _json.dumps([c[1] for c in cat_sorted])
        bar_colors = _json.dumps(['#3b82f6','#8b5cf6','#06b6d4','#10b981','#f59e0b',
                                   '#f97316','#ef4444','#dc2626','#a855f7','#14b8a6',
                                   '#ec4899','#84cc16'])

        protos     = dict(list(analysis.get('protocols',{}).items())[:8])
        proto_lbl  = _json.dumps(list(protos.keys()))
        proto_data = _json.dumps(list(protos.values()))
        proto_clrs = _json.dumps(['#3b82f6','#8b5cf6','#06b6d4','#22c55e','#f59e0b','#f97316','#a855f7','#14b8a6'])

        talkers    = list(analysis.get('top_talkers_src',{}).items())[:10]
        bubble_ds  = [{'x':i+1,'y':cnt,'r':min(int((cnt**0.5)/3)+4,40)} for i,(ip,cnt) in enumerate(talkers)]
        bubble_data= _json.dumps(bubble_ds)
        bubble_lbl = _json.dumps([ip for ip,_ in talkers])
        bubble_clrs= _json.dumps(['rgba(59,130,246,0.7)','rgba(139,92,246,0.7)',
                                   'rgba(6,182,212,0.7)','rgba(34,197,94,0.7)',
                                   'rgba(245,158,11,0.7)','rgba(249,115,22,0.7)',
                                   'rgba(239,68,68,0.7)','rgba(168,85,247,0.7)',
                                   'rgba(20,184,166,0.7)','rgba(236,72,153,0.7)'])

        tactic_list= sorted(tactic_counts.items(), key=lambda x:-x[1])
        tactic_lbl = _json.dumps([t[0] for t in tactic_list])
        tactic_dat = _json.dumps([t[1] for t in tactic_list])
        tactic_clr = _json.dumps(['#ef4444','#f97316','#eab308','#22c55e',
                                   '#3b82f6','#8b5cf6','#ec4899','#14b8a6'])

        sev_score_map = {'critical':100,'high':80,'medium':50,'low':25,'info':5}
        timeline_pts  = [{'x':i,'y':sev_score_map.get(a.get('severity','info'),5)}
                         for i,a in enumerate(anomalies[:100])]
        timeline_data = _json.dumps(timeline_pts)

        # ── gauge SVG ─────────────────────────────────────────────────────────
        g_r = 44; g_c = 60; g_circ = 2*3.14159*g_r
        g_dash = g_circ * score / 100
        gauge_svg = (f'<svg width="120" height="120" viewBox="0 0 120 120">'
                     f'<circle cx="{g_c}" cy="{g_c}" r="{g_r}" fill="none" stroke="#e2e8f0" stroke-width="12"/>'
                     f'<circle cx="{g_c}" cy="{g_c}" r="{g_r}" fill="none" stroke="{SC}" stroke-width="12" '
                     f'stroke-dasharray="{g_dash:.1f} {g_circ:.1f}" stroke-linecap="round" transform="rotate(-90 60 60)"/></svg>')

        # ════════════════════════════════════════════════════════════════════
        # CSS — light professional theme
        # ════════════════════════════════════════════════════════════════════
        CSS = f"""<style>
:root{{
  --bg:#f0f4f8; --bg2:#e8eef5; --bg3:#dce5ef; --card:#ffffff;
  --bdr:#cbd5e1; --bdr2:#b0bec9; --txt:#1e293b; --txt2:#475569;
  --mut:#94a3b8; --acc:#2563eb; --acc2:#1d4ed8; --grn:#16a34a;
  --ylw:#ca8a04; --org:#ea580c; --red:#dc2626; --cri:#991b1b;
  --pur:#7c3aed; --cyn:#0891b2; --pk:#db2777; --tl:#0d9488;
  --mono:'Consolas','Courier New',monospace;
  --sans:-apple-system,'Segoe UI','Inter',sans-serif;
  --shadow:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.04);
  --shadow-md:0 4px 6px rgba(0,0,0,.07),0 2px 4px rgba(0,0,0,.04);
}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:var(--sans);background:var(--bg);color:var(--txt);line-height:1.5;font-size:14px}}
a{{color:var(--acc);text-decoration:none}}
a:hover{{text-decoration:underline}}
.ctr{{max-width:1440px;margin:0 auto;padding:1.5rem 2rem}}

/* ── Top banner ── */
.cls-banner{{background:linear-gradient(90deg,#1e3a5f,#1d4ed8,#1e3a5f);
  text-align:center;padding:.4rem;font-size:.72rem;font-weight:700;
  letter-spacing:3px;color:#e0f2fe;text-transform:uppercase}}

/* ── Header ── */
.hdr{{background:#ffffff;border:1px solid var(--bdr);border-radius:16px;
  padding:2rem;margin-bottom:1.5rem;
  box-shadow:var(--shadow-md);position:relative;overflow:hidden}}
.hdr::before{{content:'';position:absolute;top:0;left:0;right:0;height:5px;
  background:linear-gradient(90deg,#dc2626,#ea580c,#ca8a04,#2563eb,#7c3aed,#0891b2)}}
.hdr-inner{{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem}}
.brand-line{{font-size:.78rem;font-weight:800;letter-spacing:4px;color:var(--acc);
  text-transform:uppercase;margin-bottom:.5rem}}
.brand-line a{{color:var(--acc);font-weight:800}}
.report-title{{font-size:1.75rem;font-weight:800;color:var(--txt);margin-bottom:.25rem}}
.report-sub{{color:var(--txt2);font-size:.88rem}}
.hdr-meta{{text-align:right;font-family:var(--mono);font-size:.76rem;color:var(--txt2);
  background:var(--bg);border:1px solid var(--bdr);border-radius:8px;padding:.75rem 1rem}}
.hdr-meta span{{display:block;margin-bottom:.2rem}}
.risk-badge{{display:inline-flex;align-items:center;gap:.5rem;padding:.45rem 1.1rem;
  border-radius:8px;font-size:.82rem;font-weight:800;text-transform:uppercase;
  letter-spacing:2px;margin-top:.75rem;border:2px solid {risk_color};color:{risk_color};
  background:{risk_color}18}}
.risk-badge .pulse{{width:8px;height:8px;border-radius:50%;background:{risk_color};animation:pulse 1.5s infinite}}
@keyframes pulse{{0%,100%{{opacity:1;transform:scale(1)}}50%{{opacity:.4;transform:scale(1.3)}}}}

/* ── Score ── */
.score-section{{display:flex;align-items:center;gap:2rem;flex-wrap:wrap;
  background:#fff;border:1px solid var(--bdr);border-radius:12px;
  padding:1.25rem 1.5rem;margin-bottom:1.5rem;box-shadow:var(--shadow)}}
.gauge-wrap{{position:relative;width:120px;height:120px;flex-shrink:0}}
.gauge-val{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}}
.gv{{font-size:1.75rem;font-weight:700;color:{SC};font-family:var(--mono)}}
.gl{{font-size:.62rem;color:var(--mut);text-transform:uppercase;letter-spacing:1px}}
.score-details{{flex:1}}
.score-bar-wrap{{background:var(--bg2);border-radius:8px;height:14px;overflow:hidden;
  margin:.5rem 0;border:1px solid var(--bdr)}}
.score-bar{{height:100%;border-radius:8px;background:linear-gradient(90deg,{SC}99,{SC})}}

/* ── Summary cards ── */
.sumbar{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:1rem;margin-bottom:1.5rem}}
.scard{{background:#fff;border:1px solid var(--bdr);border-radius:12px;padding:1rem;
  text-align:center;box-shadow:var(--shadow);transition:transform .15s,box-shadow .15s;position:relative}}
.scard:hover{{transform:translateY(-2px);box-shadow:var(--shadow-md)}}
.scard::after{{content:'';position:absolute;bottom:0;left:0;right:0;height:3px;
  border-radius:0 0 12px 12px;background:var(--accent-color,var(--acc))}}
.sv{{font-size:1.5rem;font-weight:700;font-family:var(--mono);color:var(--sv-color,var(--acc))}}
.sl{{font-size:.68rem;color:var(--txt2);text-transform:uppercase;letter-spacing:.8px;margin-top:.2rem}}

/* ── Section card ── */
.sec{{background:#fff;border:1px solid var(--bdr);border-radius:12px;
  margin-bottom:1.5rem;overflow:hidden;box-shadow:var(--shadow)}}
.sh{{padding:.9rem 1.4rem;border-bottom:1px solid var(--bdr);
  background:var(--bg);display:flex;align-items:center;justify-content:space-between;gap:.75rem}}
.sh-title{{font-weight:700;font-size:.92rem;color:var(--txt);display:flex;align-items:center;gap:.5rem}}
.sh-icon{{width:22px;height:22px;border-radius:5px;display:flex;align-items:center;
  justify-content:center;font-size:.85rem}}
.sh-count{{font-family:var(--mono);font-size:.78rem;color:var(--txt2);
  background:#fff;border:1px solid var(--bdr);border-radius:20px;padding:.15rem .7rem}}
.sbd{{padding:1.25rem 1.5rem}}

/* ── Tables ── */
table{{width:100%;border-collapse:collapse}}
th{{text-align:left;padding:.6rem .9rem;background:var(--bg2);
  color:var(--txt2);font-size:.7rem;text-transform:uppercase;letter-spacing:.8px;
  border-bottom:1px solid var(--bdr);white-space:nowrap;font-weight:700}}
td{{padding:.55rem .9rem;border-bottom:1px solid var(--bdr);
  font-size:.84rem;vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
tr.arow:hover{{background:var(--bg)}}
.tbl-wrap{{overflow-x:auto}}

/* ── Cell types ── */
.mono{{font-family:var(--mono);font-size:.8rem}}
.ip-cell{{font-family:var(--mono);color:var(--cyn);font-size:.79rem;max-width:130px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.port-cell{{font-family:var(--mono);color:var(--pur);text-align:center}}
.num-cell{{font-family:var(--mono);text-align:right;color:var(--txt2)}}
.atk-cell{{color:var(--org);font-size:.82rem;font-weight:600;max-width:160px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.cat-cell{{font-size:.73rem;color:var(--txt2);text-transform:uppercase;letter-spacing:.5px}}
.desc-cell{{color:var(--txt);font-size:.8rem;max-width:260px}}

/* ── Severity badges ── */
.sev-badge{{display:inline-block;padding:.15rem .55rem;border-radius:4px;
  font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.7px;font-family:var(--mono)}}
.sev-crit{{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}}
.sev-high{{background:#fee2e2;color:#b91c1c;border:1px solid #f87171}}
.sev-med{{background:#ffedd5;color:#c2410c;border:1px solid #fb923c}}
.sev-low{{background:#fef9c3;color:#854d0e;border:1px solid #fde047}}
.sev-info{{background:#dbeafe;color:#1e40af;border:1px solid #93c5fd}}

/* ── MITRE badge with link ── */
.mitre-tag{{display:inline-block;padding:.12rem .5rem;border-radius:4px;font-size:.7rem;
  font-family:var(--mono);font-weight:700;background:#ede9fe;color:#5b21b6;
  border:1px solid #c4b5fd;white-space:nowrap}}
.mitre-tag a{{color:#5b21b6;font-weight:700}}
.mitre-tag a:hover{{text-decoration:underline}}

/* ── Protocol badge ── */
.proto-badge{{display:inline-block;padding:.1rem .5rem;border-radius:4px;
  font-size:.7rem;font-weight:700;font-family:var(--mono)}}
.proto-tcp{{background:#dbeafe;color:#1e40af;border:1px solid #93c5fd}}
.proto-udp{{background:#dcfce7;color:#166534;border:1px solid #86efac}}
.proto-icmp{{background:#ffedd5;color:#c2410c;border:1px solid #fb923c}}
.proto-{{background:var(--bg2);color:var(--txt2)}}

/* ── Direction tag ── */
.dir-tag{{display:inline-block;padding:.1rem .5rem;border-radius:4px;font-size:.7rem;font-weight:600}}
.dir-ie{{background:#fee2e2;color:#b91c1c;border:1px solid #fca5a5}}
.dir-ee{{background:#fff7ed;color:#c2410c;border:1px solid #fb923c}}
.dir-ii{{background:#dbeafe;color:#1e40af;border:1px solid #93c5fd}}

/* ── Severity summary boxes ── */
.sev-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:.75rem;margin-bottom:1.25rem}}
.sev-box{{border-radius:10px;padding:.9rem;text-align:center;border:1px solid}}
.sev-box .count{{font-size:2rem;font-weight:800;font-family:var(--mono);line-height:1}}
.sev-box .label{{font-size:.65rem;text-transform:uppercase;letter-spacing:1.5px;margin-top:.3rem;font-weight:700}}
.sbox-crit{{background:#fee2e2;color:#991b1b;border-color:#fca5a5}}
.sbox-high{{background:#fee2e2;color:#b91c1c;border-color:#f87171}}
.sbox-med{{background:#ffedd5;color:#c2410c;border-color:#fb923c}}
.sbox-low{{background:#fef9c3;color:#854d0e;border-color:#fde047}}
.sbox-info{{background:#dbeafe;color:#1e40af;border-color:#93c5fd}}

/* ── Chart grid ── */
.chart-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1.5rem;margin-bottom:1.5rem}}
.chart-card{{background:#fff;border:1px solid var(--bdr);border-radius:12px;
  padding:1.25rem;box-shadow:var(--shadow)}}
.chart-title{{font-size:.8rem;font-weight:700;color:var(--txt2);text-transform:uppercase;
  letter-spacing:1px;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem}}
.chart-title::before{{content:'';display:block;width:4px;height:14px;border-radius:2px;background:var(--acc)}}
.chart-container{{position:relative;height:220px}}
.chart-container.tall{{height:280px}}
.chart-container.wide{{height:190px}}

/* ── MITRE detail table ── */
.mitre-detail-row{{display:grid;grid-template-columns:auto 1fr auto;gap:.75rem;
  align-items:center;padding:.6rem .5rem;border-bottom:1px solid var(--bdr)}}
.mitre-detail-row:last-child{{border-bottom:none}}
.mitre-id-badge{{font-family:var(--mono);font-size:.78rem;font-weight:700;
  background:#ede9fe;color:#5b21b6;border:1px solid #c4b5fd;
  border-radius:5px;padding:.2rem .6rem;white-space:nowrap;min-width:90px;text-align:center}}
.mitre-id-badge a{{color:#5b21b6}}
.mitre-info{{flex:1}}
.mitre-tname{{font-size:.85rem;font-weight:600;color:var(--txt)}}
.mitre-tactic{{display:inline-block;font-size:.68rem;font-weight:700;text-transform:uppercase;
  letter-spacing:.5px;padding:.1rem .4rem;border-radius:3px;margin-top:.15rem;
  background:#dbeafe;color:#1e40af;border:1px solid #93c5fd}}
.mitre-tdesc{{font-size:.75rem;color:var(--txt2);margin-top:.2rem}}
.mitre-cnt-badge{{font-family:var(--mono);font-size:.85rem;font-weight:700;
  background:var(--bg2);color:var(--txt2);border-radius:20px;
  padding:.15rem .6rem;border:1px solid var(--bdr)}}
.mitre-bar-outer{{background:var(--bg2);border-radius:4px;height:6px;
  margin-top:.4rem;border:1px solid var(--bdr)}}
.mitre-bar-inner{{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--pur),var(--acc))}}

/* ── Filter bar ── */
.filter-bar{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}}
.fbtn{{padding:.3rem .9rem;border-radius:20px;font-size:.73rem;font-weight:700;
  cursor:pointer;border:1.5px solid;background:#fff;font-family:var(--mono);
  text-transform:uppercase;letter-spacing:.5px;transition:all .15s;color:var(--txt2)}}
.fbtn:hover{{transform:scale(1.02)}}
.fbtn.active{{color:#fff!important}}
.fbtn-all{{border-color:var(--acc);color:var(--acc)}}.fbtn-all.active{{background:var(--acc)}}
.fbtn-crit{{border-color:var(--cri);color:var(--cri)}}.fbtn-crit.active{{background:var(--cri)}}
.fbtn-high{{border-color:var(--red);color:var(--red)}}.fbtn-high.active{{background:var(--red)}}
.fbtn-med{{border-color:var(--org);color:var(--org)}}.fbtn-med.active{{background:var(--org)}}
.fbtn-low{{border-color:var(--ylw);color:var(--ylw)}}.fbtn-low.active{{background:var(--ylw)}}

/* ── Hunting logic block ── */
.hunt-block{{background:#f8fafc;border:1px solid var(--bdr);border-left:4px solid var(--acc);
  border-radius:6px;padding:.9rem;margin:.5rem 0;font-family:var(--mono);font-size:.78rem;
  color:var(--txt);line-height:1.8;position:relative}}
.hunt-block::before{{content:'Logic';position:absolute;top:-10px;left:10px;
  font-size:.62rem;font-weight:700;letter-spacing:1px;color:var(--txt2);
  background:#f8fafc;padding:0 .4rem;text-transform:uppercase;border:1px solid var(--bdr);border-radius:3px}}
.hunt-block .kw{{color:var(--acc);font-weight:700}}
.hunt-block .val{{color:var(--red);font-weight:600}}
.hunt-block .op{{color:var(--org)}}

/* ── IR Playbook ── */
.ir-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1.25rem}}
.ir-phase{{border-left:3px solid var(--acc);padding-left:1rem;padding:1rem;
  background:#f8fafc;border-radius:8px;border:1px solid var(--bdr)}}
.ir-phase-title{{font-weight:700;font-size:.88rem;color:var(--txt);margin-bottom:.6rem;
  padding-bottom:.4rem;border-bottom:1px solid var(--bdr)}}
.ir-step{{display:flex;gap:.5rem;align-items:flex-start;padding:.25rem 0}}
.ir-num{{width:20px;height:20px;border-radius:50%;background:var(--acc);color:#fff;
  font-size:.68rem;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:.05rem}}
.ir-txt{{font-size:.8rem;color:var(--txt2);line-height:1.5}}

/* ── IOC ── */
.ioc-type{{display:inline-block;padding:.1rem .5rem;border-radius:4px;font-size:.7rem;
  font-weight:700;text-transform:uppercase;background:#dbeafe;color:#1e40af;
  border:1px solid #93c5fd;min-width:80px;text-align:center}}

/* ── Tactic badge ── */
.tactic-badge{{display:inline-block;padding:.12rem .5rem;border-radius:4px;
  font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;
  background:#f0fdf4;color:#166534;border:1px solid #bbf7d0}}

/* ── Footer ── */
.ftr{{text-align:center;padding:2rem 1rem;color:var(--txt2);font-size:.78rem;
  border-top:1px solid var(--bdr);margin-top:1rem}}

/* ── Print ── */
@media print{{body{{background:#fff}}.chart-grid{{break-inside:avoid}}}}

/* ── Scrollbar ── */
::-webkit-scrollbar{{width:6px;height:6px}}
::-webkit-scrollbar-track{{background:var(--bg2)}}
::-webkit-scrollbar-thumb{{background:var(--bdr2);border-radius:3px}}
</style>"""

        # ════════════════════════════════════════════════════════════════════
        # BUILD HTML
        # ════════════════════════════════════════════════════════════════════
        h = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Threat Hunting Report — {e(file_info.get('filename',''))} | HACKFORLAB</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
{CSS}
</head><body>
<div class="cls-banner">
  &#9888;&nbsp; THREAT INTELLIGENCE REPORT &mdash; FOR OFFICIAL USE ONLY &mdash;
  <a href="https://hackforlab.com/" target="_blank" style="color:#bfdbfe;text-decoration:underline">HACKFORLAB</a>
  PROPRIETARY &nbsp;&#9888;
</div>
<div class="ctr">

<!-- HEADER -->
<div class="hdr">
  <div class="hdr-inner">
    <div>
      <div class="brand-line">
        <a href="https://hackforlab.com/" target="_blank">HACKFORLAB</a>
        &nbsp;&bull;&nbsp; Threat Intelligence Labs
      </div>
      <div class="report-title">Passive Threat Hunting Report</div>
      <div class="report-sub">
        Network-Based Attack Detection (NABD/NBAD) &bull; Deep Packet Inspection &bull; PCAP Forensics &bull; MITRE ATT&amp;CK Mapped
      </div>
      <div class="risk-badge">
        <div class="pulse"></div>
        THREAT LEVEL: {risk}
      </div>
    </div>
    <div class="hdr-meta">
      <span>&#128196; Report ID: {rid}</span>
      <span>&#128197; Generated: {ts}</span>
      <span>&#9881; Engine: {TOOL_NAME} v{VERSION}</span>
      <span>&#128194; File: {e(file_info.get('filename',''))}</span>
      <span>&#128178; Size: {e(file_info.get('size_human',''))}</span>
      <span>&#128272; SHA-256: {e(file_info.get('sha256','')[:20])}&#8230;</span>
    </div>
  </div>
</div>

<!-- THREAT SCORE -->
<div class="score-section">
  <div class="gauge-wrap">
    {gauge_svg}
    <div class="gauge-val"><div class="gv">{score}</div><div class="gl">/ 100</div></div>
  </div>
  <div class="score-details">
    <div style="font-size:.88rem;font-weight:700;color:var(--txt2);text-transform:uppercase;letter-spacing:1px">Threat Score</div>
    <div class="score-bar-wrap"><div class="score-bar" style="width:{score}%"></div></div>
    <div style="font-size:.78rem;color:var(--mut);margin-top:.2rem">
      {sev['critical']} Critical &bull; {sev['high']} High &bull; {sev['medium']} Medium
      &bull; {sev['low']} Low &bull; {sev['info']} Info
      &nbsp;|&nbsp; {len(anomalies)} Total Detections &nbsp;&bull;&nbsp;
      {len(analysis.get('iocs',[]))} IOCs &nbsp;&bull;&nbsp;
      {len(mitre_seen)} MITRE Techniques
    </div>
  </div>
</div>

<!-- SUMMARY CARDS -->
<div class="sumbar">
  <div class="scard" style="--sv-color:var(--acc);--accent-color:var(--acc)">
    <div class="sv">{s.get('total_packets',0):,}</div><div class="sl">Packets</div></div>
  <div class="scard" style="--sv-color:var(--cyn);--accent-color:var(--cyn)">
    <div class="sv">{s.get('total_bytes_human','0 B')}</div><div class="sl">Total Data</div></div>
  <div class="scard" style="--sv-color:var(--pur);--accent-color:var(--pur)">
    <div class="sv">{s.get('duration_human','0:00')}</div><div class="sl">Duration</div></div>
  <div class="scard" style="--sv-color:var(--grn);--accent-color:var(--grn)">
    <div class="sv">{s.get('unique_ips',0)}</div><div class="sl">Unique IPs</div></div>
  <div class="scard" style="--sv-color:var(--org);--accent-color:var(--org)">
    <div class="sv">{s.get('external_ips',0)}</div><div class="sl">External IPs</div></div>
  <div class="scard" style="--sv-color:var(--tl);--accent-color:var(--tl)">
    <div class="sv">{s.get('total_flows',0)}</div><div class="sl">Flows</div></div>
  <div class="scard" style="--sv-color:var(--ylw);--accent-color:var(--ylw)">
    <div class="sv">{analysis.get('dns',{}).get('total_queries',0)}</div><div class="sl">DNS Queries</div></div>
  <div class="scard" style="--sv-color:var(--pk);--accent-color:var(--pk)">
    <div class="sv">{analysis.get('http',{}).get('total_requests',0)}</div><div class="sl">HTTP Reqs</div></div>
  <div class="scard" style="--sv-color:var(--pur);--accent-color:var(--pur)">
    <div class="sv">{len(mitre_seen)}</div><div class="sl">MITRE Techs</div></div>
  <div class="scard" style="--sv-color:{SC};--accent-color:{SC}">
    <div class="sv" style="color:{SC}">{score}/100</div><div class="sl">Threat Score</div></div>
</div>
"""
        # ── CHARTS ────────────────────────────────────────────────────────────
        h += """<!-- VISUALIZATIONS -->
<div class="chart-grid">
  <div class="chart-card">
    <div class="chart-title">Anomaly Severity Distribution</div>
    <div class="chart-container"><canvas id="sevChart"></canvas></div>
  </div>
  <div class="chart-card">
    <div class="chart-title">Attack Category Breakdown</div>
    <div class="chart-container"><canvas id="catChart"></canvas></div>
  </div>
  <div class="chart-card">
    <div class="chart-title">MITRE ATT&amp;CK Tactic Distribution</div>
    <div class="chart-container"><canvas id="tacticChart"></canvas></div>
  </div>
  <div class="chart-card">
    <div class="chart-title">Protocol Distribution</div>
    <div class="chart-container"><canvas id="protoChart"></canvas></div>
  </div>
</div>
<div class="chart-grid">
  <div class="chart-card" style="grid-column:1/-1">
    <div class="chart-title">Detection Timeline (Severity over Sequence)</div>
    <div class="chart-container wide"><canvas id="timelineChart"></canvas></div>
  </div>
</div>
<div class="chart-grid">
  <div class="chart-card" style="grid-column:1/-1">
    <div class="chart-title">Top Talkers — Bubble Size = Packet Volume</div>
    <div class="chart-container wide"><canvas id="bubbleChart"></canvas></div>
  </div>
</div>
"""

        h += f"""<script>
Chart.defaults.color = '#475569';
Chart.defaults.borderColor = '#e2e8f0';
const gridOpts = {{ color:'#f1f5f9' }};

new Chart('sevChart',{{type:'doughnut',
  data:{{labels:{sev_labels},datasets:[{{data:{sev_data},backgroundColor:{sev_colors},
    borderColor:'#ffffff',borderWidth:3}}]}},
  options:{{responsive:true,maintainAspectRatio:false,cutout:'60%',
    plugins:{{legend:{{position:'right',labels:{{font:{{size:11}},boxWidth:12}}}}}}}}
}});

new Chart('catChart',{{type:'bar',
  data:{{labels:{cat_labels},datasets:[{{label:'Detections',data:{cat_data},
    backgroundColor:{bar_colors},borderRadius:4,borderSkipped:false}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{display:false}}}},
    scales:{{x:{{ticks:{{font:{{size:10}},maxRotation:45}},grid:gridOpts}},
             y:{{ticks:{{font:{{size:10}}}},grid:gridOpts}}}}
  }}
}});

new Chart('tacticChart',{{type:'polarArea',
  data:{{labels:{tactic_lbl},datasets:[{{data:{tactic_dat},backgroundColor:{tactic_clr},
    borderColor:'#ffffff',borderWidth:2}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{position:'right',labels:{{font:{{size:10}},boxWidth:10}}}}}}
  }}
}});

new Chart('protoChart',{{type:'doughnut',
  data:{{labels:{proto_lbl},datasets:[{{data:{proto_data},backgroundColor:{proto_clrs},
    borderColor:'#ffffff',borderWidth:3}}]}},
  options:{{responsive:true,maintainAspectRatio:false,cutout:'55%',
    plugins:{{legend:{{position:'right',labels:{{font:{{size:11}},boxWidth:12}}}}}}}}
}});

new Chart('timelineChart',{{type:'scatter',
  data:{{datasets:[{{label:'Severity Score',data:{timeline_data},
    backgroundColor:'rgba(220,38,38,.55)',pointRadius:5,pointHoverRadius:7,
    borderColor:'rgba(220,38,38,.8)',borderWidth:1}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{display:false}}}},
    scales:{{x:{{ticks:{{font:{{size:10}}}},grid:gridOpts,title:{{display:true,text:'Detection #',font:{{size:10}}}}}},
             y:{{min:0,max:110,ticks:{{font:{{size:10}}}},grid:gridOpts,
                  title:{{display:true,text:'Severity Score',font:{{size:10}}}}}}}}
  }}
}});

new Chart('bubbleChart',{{type:'bubble',
  data:{{labels:{bubble_lbl},
    datasets:[{{label:'Packets',data:{bubble_data},backgroundColor:{bubble_clrs},
      borderColor:'rgba(37,99,235,.4)',borderWidth:1}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{display:false}},
      tooltip:{{callbacks:{{label:function(ctx){{
        var lbl={bubble_lbl};
        return (lbl[ctx.dataIndex]||'')+': '+ctx.parsed.y+' pkts';
      }}}}}}
    }},
    scales:{{x:{{display:false}},y:{{ticks:{{font:{{size:10}}}},grid:gridOpts,
               title:{{display:true,text:'Packets',font:{{size:10}}}}}}}}
  }}
}});

// Filter buttons
document.querySelectorAll('.fbtn').forEach(btn=>{{
  btn.addEventListener('click',function(){{
    document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));
    this.classList.add('active');
    var f=this.dataset.filter;
    document.querySelectorAll('.arow').forEach(row=>{{
      row.style.display=(f==='all'||row.dataset.sev===f)?'':'none';
    }});
  }});
}});
</script>
"""

        # ── SEVERITY OVERVIEW ─────────────────────────────────────────────────
        h += f"""<!-- SEVERITY OVERVIEW -->
<div class="sec">
  <div class="sh">
    <div class="sh-title"><span class="sh-icon" style="background:#fee2e2">&#9888;</span> Detection Summary by Severity</div>
  </div>
  <div class="sbd">
    <div class="sev-grid">
      <div class="sev-box sbox-crit"><div class="count">{sev['critical']}</div><div class="label">Critical</div></div>
      <div class="sev-box sbox-high"><div class="count">{sev['high']}</div><div class="label">High</div></div>
      <div class="sev-box sbox-med"><div class="count">{sev['medium']}</div><div class="label">Medium</div></div>
      <div class="sev-box sbox-low"><div class="count">{sev['low']}</div><div class="label">Low</div></div>
      <div class="sev-box sbox-info"><div class="count">{sev['info']}</div><div class="label">Info</div></div>
    </div>
  </div>
</div>
"""

        # ── ANOMALY TABLE ─────────────────────────────────────────────────────
        if anomalies:
            h += f"""<!-- ANOMALIES -->
<div class="sec">
  <div class="sh">
    <div class="sh-title"><span class="sh-icon" style="background:#fee2e2">&#128270;</span> Anomaly &amp; Threat Detections</div>
    <div class="sh-count">{len(anomalies)} detections</div>
  </div>
  <div class="sbd">
    <div class="filter-bar">
      <button class="fbtn fbtn-all active" data-filter="all">All ({len(anomalies)})</button>
      <button class="fbtn fbtn-crit" data-filter="critical">Critical ({sev['critical']})</button>
      <button class="fbtn fbtn-high" data-filter="high">High ({sev['high']})</button>
      <button class="fbtn fbtn-med" data-filter="medium">Medium ({sev['medium']})</button>
      <button class="fbtn fbtn-low" data-filter="low">Low ({sev['low']})</button>
    </div>
    <div class="tbl-wrap"><table>
      <thead><tr>
        <th>Severity</th><th>Source IP</th><th>Src Port</th>
        <th>Dest IP</th><th>Dst Port</th><th>Flows/Count</th>
        <th>Attack Name</th><th>MITRE Technique</th><th>Tactic</th>
        <th>Category</th><th>Description</th>
      </tr></thead>
      <tbody>
"""
            for a in anomalies:
                sv_k  = a.get('severity','info')
                svcls = {'critical':'sev-crit','high':'sev-high','medium':'sev-med',
                         'low':'sev-low','info':'sev-info'}.get(sv_k,'sev-info')
                src   = a.get('source','') or (a.get('extra',{}).get('src_ip','') if a.get('extra') else '')
                dst   = a.get('destination','') or (a.get('extra',{}).get('dst_ip','') if a.get('extra') else '')
                sp    = a.get('extra',{}).get('src_port','') if a.get('extra') else ''
                dp    = a.get('extra',{}).get('dst_port','') if a.get('extra') else ''
                flows = ''
                if a.get('extra'):
                    flows = (a['extra'].get('target_count','') or a['extra'].get('connection_count','')
                             or a['extra'].get('upload_count','') or '')
                atk   = (a.get('extra',{}).get('attack_name','') if a.get('extra') else '') or a.get('description','')[:50]
                mid   = a.get('mitre','')
                minfo = ReportGenerator._mitre_info(mid) if mid else {}
                tactic = minfo.get('tactic','') if minfo else ''
                murl  = minfo.get('url','') if minfo else ''
                desc  = a.get('description','')
                cat   = a.get('category','')
                mtag  = (f'<span class="mitre-tag"><a href="{e(murl)}" target="_blank" title="{e(minfo.get("name",""))}">{e(mid)}</a></span>'
                         if mid else '—')
                h += (f'<tr class="arow" data-sev="{sv_k}">'
                      f'<td><span class="sev-badge {svcls}">{e(sv_k.upper())}</span></td>'
                      f'<td class="ip-cell mono" title="{e(src)}">{e(src) or "—"}</td>'
                      f'<td class="port-cell mono">{e(sp) or "—"}</td>'
                      f'<td class="ip-cell mono" title="{e(dst)}">{e(dst) or "—"}</td>'
                      f'<td class="port-cell mono">{e(dp) or "—"}</td>'
                      f'<td class="num-cell">{e(flows) or "—"}</td>'
                      f'<td class="atk-cell" title="{e(atk)}">{e(atk)}</td>'
                      f'<td>{mtag}</td>'
                      f'<td><span class="tactic-badge">{e(tactic)}</span></td>'
                      f'<td class="cat-cell">{e(cat)}</td>'
                      f'<td class="desc-cell" title="{e(desc)}">{e(desc[:95])}{"…" if len(desc)>95 else ""}</td>'
                      f'</tr>')
            h += '</tbody></table></div></div></div>\n'

        # ── MITRE ATT&CK FULL DETAIL TABLE ────────────────────────────────────
        if mitre_seen:
            max_m = max(mitre_seen.values())
            h += f"""<!-- MITRE DETAIL -->
<div class="sec">
  <div class="sh">
    <div class="sh-title"><span class="sh-icon" style="background:#ede9fe">&#128737;</span> MITRE ATT&amp;CK Full Coverage — Techniques &amp; Sub-Techniques</div>
    <div class="sh-count">{len(mitre_seen)} techniques detected</div>
  </div>
  <div class="sbd">
    <p style="font-size:.82rem;color:var(--txt2);margin-bottom:1.25rem">
      All detections are mapped to the
      <a href="https://attack.mitre.org/" target="_blank">MITRE ATT&amp;CK Enterprise Framework</a>.
      Each technique and sub-technique is linked directly to the official MITRE knowledge base.
    </p>
"""
            # Group by tactic
            by_tactic = {}
            for tid, cnt in sorted(mitre_seen.items(), key=lambda x: -x[1]):
                info = ReportGenerator._mitre_info(tid)
                t = info.get('tactic','Unknown')
                if t not in by_tactic:
                    by_tactic[t] = []
                by_tactic[t].append((tid, cnt, info))

            for tactic, items in sorted(by_tactic.items()):
                tactic_total = sum(c for _,c,_ in items)
                h += f'<div style="margin-bottom:1.5rem"><div style="font-size:.82rem;font-weight:700;color:var(--acc);text-transform:uppercase;letter-spacing:1px;margin-bottom:.6rem;padding-bottom:.4rem;border-bottom:2px solid var(--acc)">&#9658; {e(tactic)} <span style="font-size:.75rem;color:var(--txt2);font-weight:400">({tactic_total} detections)</span></div>\n'
                for tid, cnt, info in items:
                    bar_w = int(cnt / max_m * 100)
                    is_sub = '.' in tid
                    indent = 'margin-left:1.5rem;' if is_sub else ''
                    sub_icon = '&#8627;' if is_sub else '&#9670;'
                    h += (f'<div class="mitre-detail-row" style="{indent}">'
                          f'<div class="mitre-id-badge"><a href="{e(info.get("url","#"))}" target="_blank">{e(tid)}</a></div>'
                          f'<div class="mitre-info">'
                          f'<div class="mitre-tname">{sub_icon} {e(info.get("name",tid))}</div>'
                          f'<span class="mitre-tactic">{e(info.get("tactic",""))}</span>'
                          f'<div class="mitre-tdesc">{e(info.get("desc",""))}</div>'
                          f'<div class="mitre-bar-outer"><div class="mitre-bar-inner" style="width:{bar_w}%"></div></div>'
                          f'</div>'
                          f'<div class="mitre-cnt-badge">{cnt}</div>'
                          f'</div>\n')
                h += '</div>\n'
            h += '</div></div>\n'

        # ── FLOW TABLE ────────────────────────────────────────────────────────
        if top_flows:
            h += f"""<!-- FLOWS -->
<div class="sec">
  <div class="sh">
    <div class="sh-title"><span class="sh-icon" style="background:#dbeafe">&#128257;</span> Top Network Flows</div>
    <div class="sh-count">{len(top_flows)} flows</div>
  </div>
  <div class="sbd">
    <div class="tbl-wrap"><table>
      <thead><tr>
        <th>Source IP</th><th>Src Port</th><th>Dest IP</th><th>Dst Port</th>
        <th>Protocol</th><th>Packets</th><th>Data</th><th>Duration</th><th>Direction</th>
      </tr></thead>
      <tbody>
"""
            for fl in top_flows:
                src  = e(fl.get('src_ip',''))
                sp   = e(fl.get('src_port',''))
                dst  = e(fl.get('dst_ip',''))
                dp   = e(fl.get('dst_port',''))
                prot = e(fl.get('proto','').upper())
                pkts = fl.get('packets',0)
                byt  = e(fl.get('bytes_human',''))
                dur  = e(fl.get('duration',''))
                dire = e(fl.get('direction',''))
                dc   = 'dir-ie' if 'Ext' in dire and 'Int' in dire else 'dir-ee' if dire.count('Ext')==2 else 'dir-ii'
                h += (f'<tr><td class="ip-cell mono">{src}</td>'
                      f'<td class="port-cell mono">{sp}</td>'
                      f'<td class="ip-cell mono">{dst}</td>'
                      f'<td class="port-cell mono">{dp}</td>'
                      f'<td><span class="proto-badge proto-{prot.lower()}">{prot}</span></td>'
                      f'<td class="num-cell">{pkts:,}</td>'
                      f'<td class="num-cell">{byt}</td>'
                      f'<td class="num-cell">{dur}s</td>'
                      f'<td><span class="dir-tag {dc}">{dire}</span></td></tr>')
            h += '</tbody></table></div></div></div>\n'

        # ── PROTOCOL ─────────────────────────────────────────────────────────
        protos_d = analysis.get('protocols',{})
        if protos_d:
            total_p = max(s.get('total_packets',1),1)
            h += f"""<!-- PROTOCOLS -->
<div class="sec">
  <div class="sh">
    <div class="sh-title"><span class="sh-icon" style="background:#d1fae5">&#128268;</span> Protocol Distribution</div>
  </div>
  <div class="sbd"><div class="tbl-wrap"><table>
    <thead><tr><th>Protocol</th><th>Packets</th><th>% Traffic</th><th>Visual</th></tr></thead>
    <tbody>
"""
            for p, cnt in sorted(protos_d.items(), key=lambda x:-x[1]):
                pct = cnt/total_p*100
                bc  = '#3b82f6' if p=='TCP' else '#22c55e' if p=='UDP' else '#f97316' if p=='ICMP' else '#8b5cf6'
                h += (f'<tr><td class="mono">{e(p)}</td><td class="num-cell">{cnt:,}</td>'
                      f'<td class="num-cell">{pct:.1f}%</td>'
                      f'<td style="min-width:120px"><div style="background:var(--bg2);border-radius:4px;height:8px;border:1px solid var(--bdr)">'
                      f'<div style="width:{pct:.1f}%;height:100%;border-radius:4px;background:{bc}"></div></div></td></tr>')
            h += '</tbody></table></div></div></div>\n'

        # ── DNS ───────────────────────────────────────────────────────────────
        dns = analysis.get('dns',{})
        if dns.get('total_queries',0):
            h += f"""<!-- DNS -->
<div class="sec">
  <div class="sh">
    <div class="sh-title"><span class="sh-icon" style="background:#dcfce7">&#127760;</span> DNS Analysis</div>
    <div class="sh-count">{dns['total_queries']} queries &bull; {dns.get('unique_domains',0)} unique domains</div>
  </div>
  <div class="sbd"><div class="tbl-wrap"><table>
    <thead><tr><th>Domain</th><th>Queries</th><th>Bar</th></tr></thead><tbody>
"""
            mx = max(dns.get('top_domains',{1:1}).values()) if dns.get('top_domains') else 1
            for dom, cnt in list(dns.get('top_domains',{}).items())[:20]:
                bw = int(cnt/mx*100)
                h += (f'<tr><td class="mono" style="color:var(--cyn)">{e(dom)}</td>'
                      f'<td class="num-cell">{cnt}</td>'
                      f'<td style="min-width:120px"><div style="background:var(--bg2);border-radius:3px;height:6px">'
                      f'<div style="width:{bw}%;height:100%;border-radius:3px;background:var(--grn)"></div></div></td></tr>')
            h += '</tbody></table></div></div></div>\n'

        # ── HTTP ──────────────────────────────────────────────────────────────
        http_d = analysis.get('http',{})
        if http_d.get('total_requests',0):
            h += f"""<!-- HTTP -->
<div class="sec">
  <div class="sh">
    <div class="sh-title"><span class="sh-icon" style="background:#ffedd5">&#127760;</span> HTTP Analysis</div>
    <div class="sh-count">{http_d['total_requests']} requests</div>
  </div>
  <div class="sbd"><div class="tbl-wrap"><table>
    <thead><tr><th>Method</th><th>Host</th><th>URI</th><th>Source IP</th><th>User-Agent</th></tr></thead><tbody>
"""
            for r in http_d.get('requests',[])[:20]:
                meth = r.get('method','')
                mc   = 'color:var(--red)' if meth=='POST' else 'color:var(--acc)'
                h += (f'<tr><td><span style="font-family:var(--mono);font-size:.78rem;font-weight:700;{mc}">{e(meth)}</span></td>'
                      f'<td class="mono" style="color:var(--cyn)">{e(r.get("host",""))}</td>'
                      f'<td style="font-size:.77rem;word-break:break-all;max-width:200px">{e(r.get("uri","")[:80])}</td>'
                      f'<td class="mono" style="color:var(--pur)">{e(r.get("src_ip",""))}</td>'
                      f'<td style="font-size:.72rem;color:var(--txt2);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{e(r.get("user_agent",""))}">{e(r.get("user_agent","")[:60])}</td></tr>')
            h += '</tbody></table></div></div></div>\n'

        # ── TLS ───────────────────────────────────────────────────────────────
        tls_d = analysis.get('tls',{})
        if tls_d.get('total_handshakes',0):
            h += f"""<!-- TLS -->
<div class="sec">
  <div class="sh">
    <div class="sh-title"><span class="sh-icon" style="background:#ede9fe">&#128274;</span> TLS Analysis</div>
    <div class="sh-count">{tls_d['total_handshakes']} handshakes</div>
  </div>
  <div class="sbd"><div class="tbl-wrap"><table>
    <thead><tr><th>TLS Version</th><th>Count</th><th>Status</th></tr></thead><tbody>
"""
            for v, cnt in tls_d.get('versions',{}).items():
                is_dep = 'SSL' in v or v in ('TLS 1.0','TLS 1.1')
                st = '<span class="sev-badge sev-crit">DEPRECATED</span>' if is_dep else '<span class="sev-badge sev-info">OK</span>'
                h += f'<tr><td class="mono">{e(v)}</td><td class="num-cell">{cnt}</td><td>{st}</td></tr>'
            h += '</tbody></table>'
            snis = tls_d.get('sni_list',[])
            if snis:
                h += '<p style="margin-top:.75rem;font-size:.82rem;color:var(--txt2)"><strong style="color:var(--txt)">SNI Hostnames:</strong> '
                h += ', '.join(f'<span class="mono" style="color:var(--cyn)">{e(sn)}</span>' for sn in snis[:25])
                h += '</p>'
            h += '</div></div>\n'

        # ── IOCs ──────────────────────────────────────────────────────────────
        iocs = analysis.get('iocs',[])
        if iocs:
            h += f"""<!-- IOCs -->
<div class="sec">
  <div class="sh">
    <div class="sh-title"><span class="sh-icon" style="background:#fce7f3">&#128272;</span> Indicators of Compromise (IOCs)</div>
    <div class="sh-count">{len(iocs)} IOCs</div>
  </div>
  <div class="sbd"><div class="tbl-wrap"><table>
    <thead><tr><th>IOC Type</th><th>Value</th></tr></thead><tbody>
"""
            for ioc in iocs[:60]:
                h += f'<tr><td><span class="ioc-type">{e(ioc["type"])}</span></td><td class="mono" style="color:var(--cyn);word-break:break-all">{e(ioc["value"])}</td></tr>'
            h += '</tbody></table></div></div></div>\n'

        # ── TOP TALKERS ───────────────────────────────────────────────────────
        ts_d = analysis.get('top_talkers_src',{})
        td_d = analysis.get('top_talkers_dst',{})
        if ts_d:
            h += f"""<!-- TALKERS -->
<div class="sec">
  <div class="sh">
    <div class="sh-title"><span class="sh-icon" style="background:#dbeafe">&#128242;</span> Top Talkers</div>
  </div>
  <div class="sbd" style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem">
    <div>
      <div style="font-size:.78rem;font-weight:700;color:var(--txt2);text-transform:uppercase;letter-spacing:1px;margin-bottom:.6rem">Top Source IPs</div>
      <div class="tbl-wrap"><table>
        <thead><tr><th>IP</th><th>Packets</th><th>Type</th></tr></thead><tbody>
"""
            for ip, cnt in list(ts_d.items())[:10]:
                t_cls = 'color:var(--tl)' if _is_private(ip) else 'color:var(--org)'
                t_lbl = 'Internal' if _is_private(ip) else 'External'
                h += f'<tr><td class="ip-cell mono" title="{e(ip)}">{e(ip)}</td><td class="num-cell">{cnt:,}</td><td style="font-size:.75rem;font-weight:600;{t_cls}">{t_lbl}</td></tr>'
            h += '</tbody></table></div></div>\n'
            if td_d:
                h += f"""    <div>
      <div style="font-size:.78rem;font-weight:700;color:var(--txt2);text-transform:uppercase;letter-spacing:1px;margin-bottom:.6rem">Top Destination IPs</div>
      <div class="tbl-wrap"><table>
        <thead><tr><th>IP</th><th>Packets</th><th>Type</th></tr></thead><tbody>
"""
                for ip, cnt in list(td_d.items())[:10]:
                    t_cls = 'color:var(--tl)' if _is_private(ip) else 'color:var(--org)'
                    t_lbl = 'Internal' if _is_private(ip) else 'External'
                    h += f'<tr><td class="ip-cell mono" title="{e(ip)}">{e(ip)}</td><td class="num-cell">{cnt:,}</td><td style="font-size:.75rem;font-weight:600;{t_cls}">{t_lbl}</td></tr>'
                h += '</tbody></table></div></div>'
            h += '</div></div></div>\n'

        # ── HUNTING LOGIC ─────────────────────────────────────────────────────
        h += """<!-- HUNTING LOGIC -->
<div class="sec">
  <div class="sh">
    <div class="sh-title"><span class="sh-icon" style="background:#dcfce7">&#128270;</span> NABD Hunting Logic Reference</div>
  </div>
  <div class="sbd" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.25rem">
    <div>
      <div style="font-size:.82rem;font-weight:700;color:var(--acc);margin-bottom:.4rem">&#128269; Port Scanning <span class="mitre-tag" style="margin-left:.3rem"><a href="https://attack.mitre.org/techniques/T1046/" target="_blank">T1046</a></span></div>
      <div class="hunt-block"><span class="kw">IF</span> unique(dst.port) <span class="op">&gt;</span> <span class="val">50</span><br>
<span class="kw">AND</span> tcp.flags <span class="op">=</span> <span class="val">SYN</span><br>
<span class="kw">AND</span> duration <span class="op">&lt;</span> <span class="val">60s</span><br>
<span class="kw">THEN</span> Port Scan</div>
    </div>
    <div>
      <div style="font-size:.82rem;font-weight:700;color:var(--red);margin-bottom:.4rem">&#128272; Brute Force <span class="mitre-tag" style="margin-left:.3rem"><a href="https://attack.mitre.org/techniques/T1110/" target="_blank">T1110</a></span></div>
      <div class="hunt-block"><span class="kw">IF</span> failed.auth <span class="op">&gt;</span> <span class="val">10</span><br>
<span class="kw">AND</span> same source.ip<br>
<span class="kw">AND</span> same dst.service<br>
<span class="kw">THEN</span> Brute Force</div>
    </div>
    <div>
      <div style="font-size:.82rem;font-weight:700;color:var(--pur);margin-bottom:.4rem">&#128126; C2 Beaconing <span class="mitre-tag" style="margin-left:.3rem"><a href="https://attack.mitre.org/techniques/T1071/" target="_blank">T1071</a></span></div>
      <div class="hunt-block"><span class="kw">IF</span> same dst.ip + port<br>
<span class="kw">AND</span> CV(interval) <span class="op">&lt;</span> <span class="val">0.15</span><br>
<span class="kw">AND</span> payload.size <span class="op">&lt;</span> <span class="val">200B</span><br>
<span class="kw">THEN</span> C2 Beaconing</div>
    </div>
    <div>
      <div style="font-size:.82rem;font-weight:700;color:var(--cyn);margin-bottom:.4rem">&#127760; DNS Tunneling <span class="mitre-tag" style="margin-left:.3rem"><a href="https://attack.mitre.org/techniques/T1071/004/" target="_blank">T1071.004</a></span></div>
      <div class="hunt-block"><span class="kw">IF</span> dns.query.len <span class="op">&gt;</span> <span class="val">50</span><br>
<span class="kw">AND</span> entropy <span class="op">&gt;</span> <span class="val">3.5</span><br>
<span class="kw">AND</span> repeated NXDOMAIN<br>
<span class="kw">THEN</span> DNS Tunneling</div>
    </div>
    <div>
      <div style="font-size:.82rem;font-weight:700;color:var(--org);margin-bottom:.4rem">&#128228; Exfiltration <span class="mitre-tag" style="margin-left:.3rem"><a href="https://attack.mitre.org/techniques/T1041/" target="_blank">T1041</a></span></div>
      <div class="hunt-block"><span class="kw">IF</span> outbound.bytes <span class="op">&gt;</span> baseline<br>
<span class="kw">AND</span> dst <span class="op">not</span> trusted<br>
<span class="kw">AND</span> entropy(payload) <span class="op">&gt;</span> <span class="val">7.0</span><br>
<span class="kw">THEN</span> Data Exfiltration</div>
    </div>
    <div>
      <div style="font-size:.82rem;font-weight:700;color:var(--grn);margin-bottom:.4rem">&#8594; Lateral Movement <span class="mitre-tag" style="margin-left:.3rem"><a href="https://attack.mitre.org/techniques/T1021/002/" target="_blank">T1021.002</a></span></div>
      <div class="hunt-block"><span class="kw">IF</span> SMB east-west burst<br>
<span class="kw">AND</span> same creds reused<br>
<span class="kw">AND</span> targets <span class="op">&gt;</span> <span class="val">3</span> internal<br>
<span class="kw">THEN</span> Lateral Movement</div>
    </div>
  </div>
</div>
"""

        # ── IR PLAYBOOK ───────────────────────────────────────────────────────
        h += """<!-- IR PLAYBOOK -->
<div class="sec">
  <div class="sh">
    <div class="sh-title"><span class="sh-icon" style="background:#fee2e2">&#128216;</span> IR Response Playbook — 6-Phase Model</div>
  </div>
  <div class="sbd">
    <div class="ir-grid">
      <div class="ir-phase">
        <div class="ir-phase-title" style="color:var(--acc)">&#9312; Detection &amp; Validation</div>
        <div class="ir-step"><div class="ir-num">1</div><div class="ir-txt">Validate attack patterns — incomplete handshakes, flag anomalies, volume spikes</div></div>
        <div class="ir-step"><div class="ir-num">2</div><div class="ir-txt">Confirm not authorized scanner, monitoring tool, or patching system</div></div>
        <div class="ir-step"><div class="ir-num">3</div><div class="ir-txt">Preserve: PCAP window, flow summaries, source ASN/Geo, target asset list</div></div>
      </div>
      <div class="ir-phase">
        <div class="ir-phase-title" style="color:var(--pur)">&#9313; Scoping &amp; Impact</div>
        <div class="ir-step"><div class="ir-num">1</div><div class="ir-txt">Identify affected subnets, services discovered, business criticality</div></div>
        <div class="ir-step"><div class="ir-num">2</div><div class="ir-txt">Check if attack transitioned to exploitation or authentication attempts</div></div>
        <div class="ir-step"><div class="ir-num">3</div><div class="ir-txt">Map privilege escalation path and credential exposure</div></div>
      </div>
      <div class="ir-phase">
        <div class="ir-phase-title" style="color:var(--org)">&#9314; Containment</div>
        <div class="ir-step"><div class="ir-num">1</div><div class="ir-txt">Block source IPs, apply emergency firewall ACLs, rate-limit scanning hosts</div></div>
        <div class="ir-step"><div class="ir-num">2</div><div class="ir-txt">Isolate infected segments, disable compromised accounts</div></div>
        <div class="ir-step"><div class="ir-num">3</div><div class="ir-txt">Sinkhole malicious domains, block C2 infrastructure</div></div>
      </div>
      <div class="ir-phase">
        <div class="ir-phase-title" style="color:var(--red)">&#9315; Eradication</div>
        <div class="ir-step"><div class="ir-num">1</div><div class="ir-txt">Remove malware, unauthorized tasks/services, web shells</div></div>
        <div class="ir-step"><div class="ir-num">2</div><div class="ir-txt">Patch exploited vulnerabilities, reset all compromised credentials</div></div>
        <div class="ir-step"><div class="ir-num">3</div><div class="ir-txt">Invalidate Kerberos tickets, rotate service account secrets</div></div>
      </div>
      <div class="ir-phase">
        <div class="ir-phase-title" style="color:var(--grn)">&#9316; Recovery</div>
        <div class="ir-step"><div class="ir-num">1</div><div class="ir-txt">Restore clean images, validate integrity via hash verification</div></div>
        <div class="ir-step"><div class="ir-num">2</div><div class="ir-txt">Restore normal auth services, monitor for re-attempt activity</div></div>
        <div class="ir-step"><div class="ir-num">3</div><div class="ir-txt">Notify legal/compliance if PII or regulated data affected</div></div>
      </div>
      <div class="ir-phase">
        <div class="ir-phase-title" style="color:var(--cyn)">&#9317; Lessons Learned</div>
        <div class="ir-step"><div class="ir-num">1</div><div class="ir-txt">Root cause: why was service reachable / vulnerability unpatched?</div></div>
        <div class="ir-step"><div class="ir-num">2</div><div class="ir-txt">Improve detection thresholds, add patterns to baseline</div></div>
        <div class="ir-step"><div class="ir-num">3</div><div class="ir-txt">Enforce: network segmentation, MFA, NTLMv1 disable, DLP improvements</div></div>
      </div>
    </div>
  </div>
</div>
"""

        # ── FOOTER ────────────────────────────────────────────────────────────
        h += f"""<div class="ftr">
  <a href="https://hackforlab.com/" target="_blank" style="font-weight:700;color:var(--acc)">HACKFORLAB</a>
  &mdash; Threat Intelligence Labs &mdash; {TOOL_NAME} v{VERSION}<br>
  Passive Threat Hunting Report &bull; {ts} &bull; Report ID: {rid}<br>
  {len(anomalies)} Detections &bull; {len(iocs)} IOCs &bull; {len(mitre_seen)} MITRE Techniques &bull; Threat Score: {score}/100 &bull; Risk: {risk}<br>
  <span style="font-size:.72rem;color:var(--mut)">&copy; {datetime.now().year}
  <a href="https://hackforlab.com/" target="_blank">HACKFORLAB</a> &mdash; All Rights Reserved &mdash; Authorized Security Use Only</span>
</div>

</div></body></html>"""

        with open(output_path, 'w', encoding='utf-8') as out:
            out.write(h)
        return output_path



# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SCANNER ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
class PacketCaptureAnalyzer:
    def __init__(self):
        pass

    def analyze_file(self, filepath, log_cb=None):
        def log(m):
            if log_cb: log_cb(m)
            print(m)

        log(f"[*] Analyzing: {os.path.basename(filepath)}")
        file_info = {
            'filename': os.path.basename(filepath),
            'size': os.path.getsize(filepath),
            'size_human': _human_bytes(os.path.getsize(filepath)),
        }
        with open(filepath, 'rb') as f:
            file_info['sha256'] = hashlib.sha256(f.read()).hexdigest()

        log(f"  File: {file_info['size_human']} | SHA-256: {file_info['sha256'][:16]}...")

        # Parse PCAP
        log("  [1/3] Parsing packet capture...")
        pcap_data = PcapParser.parse(filepath)
        raw_packets = pcap_data.get('packets', [])
        log(f"  [+] Format: {pcap_data['format']} | {len(raw_packets)} packets | Linktype: {pcap_data['linktype']}")

        # Dissect packets
        log("  [2/3] Dissecting protocols...")
        dissected = []
        for pkt in raw_packets:
            try:
                d = ProtocolDissector.dissect(pkt)
                dissected.append(d)
            except Exception:
                pass
        log(f"  [+] Dissected {len(dissected)} packets")

        # Analyze
        log("  [3/3] Analyzing traffic patterns & detecting anomalies...")
        analyzer = TrafficAnalyzer()
        results = analyzer.process(dissected)
        results['file_info'] = file_info
        results['pcap_info'] = {k: v for k, v in pcap_data.items() if k != 'packets'}

        s = results.get('summary', {})
        log(f"\n  RESULTS:")
        log(f"    Packets:    {s.get('total_packets',0):,}")
        log(f"    Data:       {s.get('total_bytes_human','0 B')}")
        log(f"    Duration:   {s.get('duration_human','0:00')}")
        log(f"    Unique IPs: {s.get('unique_ips',0)} ({s.get('external_ips',0)} external)")
        log(f"    Flows:      {s.get('total_flows',0)}")
        log(f"    DNS:        {results.get('dns',{}).get('total_queries',0)} queries")
        log(f"    HTTP:       {results.get('http',{}).get('total_requests',0)} requests")
        log(f"    TLS:        {results.get('tls',{}).get('total_handshakes',0)} handshakes")
        log(f"    Anomalies:  {len(results.get('anomalies',[]))}")
        log(f"    Risk:       {results.get('risk_level','CLEAN')} ({results.get('threat_score',0)}/100)")
        log(f"    IOCs:       {len(results.get('iocs',[]))}")

        for a in results.get('anomalies', [])[:10]:
            log(f"    [{a['severity'].upper():8s}] {a['description']}")

        log("")
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# TKINTER GUI
# ═══════════════════════════════════════════════════════════════════════════════

def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    from PIL import ImageTk

    class App:
        def __init__(self, root):
            self.root = root
            self.root.title(f"{TOOL_NAME} v{VERSION} — {BRAND}")
            self.root.geometry("1300x920")
            self.root.minsize(1000, 700)
            self.root.configure(bg=COLORS['bg_dark'])
            self.analyzer = PacketCaptureAnalyzer()
            self.results = None
            self._setup_styles()
            self._build()

        def _setup_styles(self):
            s = ttk.Style(); s.theme_use('clam')
            s.configure('Dark.TFrame', background=COLORS['bg_dark'])
            s.configure('Card.TFrame', background=COLORS['bg_card'])
            s.configure('Mid.TFrame', background=COLORS['bg_mid'])
            for name, bg, fg, font in [
                ('Title.TLabel', COLORS['bg_dark'], COLORS['accent'], ('Helvetica',22,'bold')),
                ('Subtitle.TLabel', COLORS['bg_dark'], COLORS['text_secondary'], ('Helvetica',11)),
                ('Brand.TLabel', COLORS['bg_dark'], COLORS['accent'], ('Helvetica',10,'bold')),
                ('Dark.TLabel', COLORS['bg_dark'], COLORS['text'], ('Helvetica',10)),
                ('Card.TLabel', COLORS['bg_card'], COLORS['text'], ('Helvetica',10)),
                ('CardMuted.TLabel', COLORS['bg_card'], COLORS['text_muted'], ('Helvetica',9)),
                ('Score.TLabel', COLORS['bg_card'], COLORS['accent'], ('Consolas',28,'bold')),
                ('StatVal.TLabel', COLORS['bg_card'], COLORS['cyan'], ('Consolas',16,'bold')),
                ('StatLbl.TLabel', COLORS['bg_card'], COLORS['text_muted'], ('Helvetica',8)),
            ]:
                s.configure(name, background=bg, foreground=fg, font=font)
            s.configure('Accent.TButton', background=COLORS['accent'], foreground=COLORS['white'], font=('Helvetica',11,'bold'), padding=(20,12))
            s.map('Accent.TButton', background=[('active',COLORS['accent_hover'])])
            s.configure('Secondary.TButton', background=COLORS['bg_card'], foreground=COLORS['text'], font=('Helvetica',10), padding=(15,10))
            s.map('Secondary.TButton', background=[('active',COLORS['border'])])
            s.configure('Small.TButton', background=COLORS['bg_card'], foreground=COLORS['text_secondary'], font=('Helvetica',9), padding=(10,6))
            s.configure('dark.Horizontal.TProgressbar', background=COLORS['accent'], troughcolor=COLORS['bg_input'])

        def _build(self):
            main = ttk.Frame(self.root, style='Dark.TFrame'); main.pack(fill=tk.BOTH, expand=True)

            # Header
            hdr = ttk.Frame(main, style='Dark.TFrame'); hdr.pack(fill=tk.X, padx=30, pady=(20,10))
            accent = tk.Canvas(hdr, height=3, bg=COLORS['bg_dark'], highlightthickness=0)
            accent.pack(fill=tk.X, pady=(0,12)); accent.update_idletasks()
            w = max(accent.winfo_width(), 800)
            accent.create_rectangle(0,0,w//3,3,fill=COLORS['accent'],outline='')
            accent.create_rectangle(w//3,0,2*w//3,3,fill=COLORS['purple'],outline='')
            accent.create_rectangle(2*w//3,0,w,3,fill=COLORS['cyan'],outline='')
            ht = ttk.Frame(hdr, style='Dark.TFrame'); ht.pack(fill=tk.X)
            lh = ttk.Frame(ht, style='Dark.TFrame'); lh.pack(side=tk.LEFT)
            ttk.Label(lh, text=BRAND, style='Brand.TLabel').pack(anchor='w')
            ttk.Label(lh, text="HFL PCAP Analyzer", style='Title.TLabel').pack(anchor='w')
            ttk.Label(lh, text="Deep Packet Inspection  •  Traffic Forensics  •  Threat Detection", style='Subtitle.TLabel').pack(anchor='w', pady=(2,0))
            ttk.Label(ttk.Frame(ht, style='Dark.TFrame'), text=f"v{VERSION}", style='Dark.TLabel').pack(anchor='e')

            # Toolbar
            tb = ttk.Frame(main, style='Dark.TFrame'); tb.pack(fill=tk.X, padx=30, pady=(10,5))
            ttk.Button(tb, text="  Open PCAP  ", style='Accent.TButton', command=self._open_pcap).pack(side=tk.LEFT, padx=(0,8))
            ttk.Button(tb, text="  Generate Demo  ", style='Secondary.TButton', command=self._gen_demo).pack(side=tk.LEFT, padx=(0,8))
            ttk.Button(tb, text="  Export Report  ", style='Secondary.TButton', command=self._export_html).pack(side=tk.RIGHT, padx=(8,0))
            ttk.Button(tb, text="  Export JSON  ", style='Small.TButton', command=self._export_json).pack(side=tk.RIGHT, padx=(8,0))
            ttk.Button(tb, text="  Clear  ", style='Small.TButton', command=self._clear).pack(side=tk.RIGHT, padx=(8,0))

            # Content
            content = ttk.Frame(main, style='Dark.TFrame'); content.pack(fill=tk.BOTH, expand=True, padx=30, pady=(10,20))

            # Left panel — stats
            left = ttk.Frame(content, style='Dark.TFrame', width=340); left.pack(side=tk.LEFT, fill=tk.Y, padx=(0,15)); left.pack_propagate(False)

            # Risk card
            rc = ttk.Frame(left, style='Card.TFrame'); rc.pack(fill=tk.X, pady=(0,10))
            ttk.Label(rc, text="THREAT ASSESSMENT", style='CardMuted.TLabel').pack(anchor='w', padx=15, pady=(12,5))
            self.risk_lbl = ttk.Label(rc, text="—", style='Score.TLabel'); self.risk_lbl.pack(padx=15, pady=(5,2))
            self.risk_desc = ttk.Label(rc, text="Awaiting analysis...", style='CardMuted.TLabel'); self.risk_desc.pack(padx=15)
            sf = ttk.Frame(rc, style='Card.TFrame'); sf.pack(fill=tk.X, padx=15, pady=(5,15))
            self.score_bar = ttk.Progressbar(sf, style='dark.Horizontal.TProgressbar', length=300, maximum=100, value=0)
            self.score_bar.pack(fill=tk.X, pady=(3,2))
            self.score_lbl = ttk.Label(sf, text="0 / 100", style='CardMuted.TLabel'); self.score_lbl.pack(anchor='e')

            # Stats card
            sc = ttk.Frame(left, style='Card.TFrame'); sc.pack(fill=tk.X, pady=(0,10))
            ttk.Label(sc, text="CAPTURE STATISTICS", style='CardMuted.TLabel').pack(anchor='w', padx=15, pady=(12,5))
            stats_grid = ttk.Frame(sc, style='Card.TFrame'); stats_grid.pack(fill=tk.X, padx=15, pady=(0,15))
            self.stat_labels = {}
            for i, (key, label) in enumerate([
                ('packets', 'Packets'), ('bytes', 'Data'), ('duration', 'Duration'),
                ('ips', 'Unique IPs'), ('flows', 'Flows'), ('anomalies', 'Anomalies'),
                ('dns', 'DNS Queries'), ('http', 'HTTP Reqs'), ('tls', 'TLS Handshakes'),
            ]):
                r, c = divmod(i, 3)
                f = ttk.Frame(stats_grid, style='Card.TFrame')
                f.grid(row=r, column=c, padx=5, pady=3, sticky='ew')
                stats_grid.columnconfigure(c, weight=1)
                val = ttk.Label(f, text="—", style='StatVal.TLabel'); val.pack()
                ttk.Label(f, text=label, style='StatLbl.TLabel').pack()
                self.stat_labels[key] = val

            # Right panel — tabs
            right = ttk.Frame(content, style='Dark.TFrame'); right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            s = ttk.Style()
            s.configure('TNotebook', background=COLORS['bg_dark'], borderwidth=0)
            s.configure('TNotebook.Tab', background=COLORS['bg_card'], foreground=COLORS['text_secondary'], padding=(12,8), font=('Helvetica',10))
            s.map('TNotebook.Tab', background=[('selected',COLORS['accent'])], foreground=[('selected',COLORS['white'])])

            self.nb = ttk.Notebook(right); self.nb.pack(fill=tk.BOTH, expand=True)
            txt_opts = dict(wrap=tk.WORD, bg=COLORS['bg_input'], fg=COLORS['text'], font=('Consolas',10), relief='flat', borderwidth=0, padx=12, pady=12)
            self.tabs = {}
            for name, fg in [("Log", COLORS['text']), ("Protocols", COLORS['cyan']), ("Flows", COLORS['text']),
                               ("DNS", COLORS['cyan']), ("HTTP", COLORS['text']), ("TLS", COLORS['purple']),
                               ("Threats", COLORS['red']), ("IOCs", COLORS['cyan'])]:
                f = ttk.Frame(self.nb, style='Card.TFrame'); self.nb.add(f, text=f" {name} ")
                t = scrolledtext.ScrolledText(f, **{**txt_opts, 'fg': fg}); t.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
                self.tabs[name] = t

            self.tabs["Log"].insert(tk.END, f"  {BRAND} — {TOOL_NAME} v{VERSION}\n  Ready. Open a PCAP file to analyze.\n\n")
            self.tabs["Log"].config(state=tk.DISABLED)

            # Status
            sb = ttk.Frame(main, style='Mid.TFrame'); sb.pack(fill=tk.X, side=tk.BOTTOM)
            self.status = ttk.Label(sb, text=f"  {BRAND} — {TOOL_NAME} v{VERSION}  |  Ready",
                                     background=COLORS['bg_mid'], foreground=COLORS['text_muted'], font=('Helvetica',9))
            self.status.pack(side=tk.LEFT, padx=10, pady=5)

        def _log(self, m):
            def _a():
                self.tabs["Log"].config(state=tk.NORMAL); self.tabs["Log"].insert(tk.END, m+"\n")
                self.tabs["Log"].see(tk.END); self.tabs["Log"].config(state=tk.DISABLED)
            self.root.after(0, _a)

        def _set_status(self, t):
            self.root.after(0, lambda: self.status.configure(text=f"  {BRAND} — {TOOL_NAME} v{VERSION}  |  {t}"))

        def _update(self, r):
            risk = r.get('risk_level','CLEAN'); score = r.get('threat_score',0)
            rc = {'CLEAN':COLORS['green'],'LOW':COLORS['yellow'],'MEDIUM':COLORS['orange'],'HIGH':COLORS['red'],'CRITICAL':COLORS['critical']}
            self.risk_lbl.configure(text=risk, foreground=rc.get(risk, COLORS['text_muted']))
            self.risk_desc.configure(text=f"Threat Score: {score}/100")
            self.score_bar['value'] = score; self.score_lbl.configure(text=f"{score} / 100")

            s = r.get('summary',{})
            self.stat_labels['packets'].configure(text=f"{s.get('total_packets',0):,}")
            self.stat_labels['bytes'].configure(text=s.get('total_bytes_human','0 B'))
            self.stat_labels['duration'].configure(text=s.get('duration_human','0:00'))
            self.stat_labels['ips'].configure(text=str(s.get('unique_ips',0)))
            self.stat_labels['flows'].configure(text=str(s.get('total_flows',0)))
            self.stat_labels['anomalies'].configure(text=str(len(r.get('anomalies',[]))))
            self.stat_labels['dns'].configure(text=str(r.get('dns',{}).get('total_queries',0)))
            self.stat_labels['http'].configure(text=str(r.get('http',{}).get('total_requests',0)))
            self.stat_labels['tls'].configure(text=str(r.get('tls',{}).get('total_handshakes',0)))

            # Protocols tab
            t = self.tabs["Protocols"]; t.delete('1.0', tk.END)
            t.insert(tk.END, f"PROTOCOL DISTRIBUTION\n{'='*60}\n\n")
            for p, c in sorted(r.get('protocols',{}).items(), key=lambda x:-x[1]):
                pct = (c/max(s.get('total_packets',1),1))*100
                bar = '#' * int(pct/2)
                t.insert(tk.END, f"  {p:12s} {c:>8,}  ({pct:5.1f}%)  {bar}\n")

            # Flows tab
            t = self.tabs["Flows"]; t.delete('1.0', tk.END)
            t.insert(tk.END, f"TOP FLOWS BY VOLUME\n{'='*60}\n\n")
            for f in r.get('top_flows',[])[:20]:
                t.insert(tk.END, f"  {f['key']}\n    Packets: {f['packets']:,}  Data: {f['bytes_human']}  Duration: {f['duration']}s\n\n")

            # DNS tab
            t = self.tabs["DNS"]; t.delete('1.0', tk.END)
            dns = r.get('dns',{})
            t.insert(tk.END, f"DNS ANALYSIS\n{'='*60}\n  Queries: {dns.get('total_queries',0)}  Unique domains: {dns.get('unique_domains',0)}\n\n")
            t.insert(tk.END, f"TOP QUERIED DOMAINS\n{'-'*40}\n")
            for d, c in list(dns.get('top_domains',{}).items())[:20]:
                t.insert(tk.END, f"  {c:>5}  {d}\n")

            # HTTP tab
            t = self.tabs["HTTP"]; t.delete('1.0', tk.END)
            http = r.get('http',{})
            t.insert(tk.END, f"HTTP ANALYSIS\n{'='*60}\n  Requests: {http.get('total_requests',0)}\n\n")
            for req in http.get('requests',[])[:30]:
                t.insert(tk.END, f"  {req.get('method',''):6s} {req.get('host','')}{req.get('uri','')}\n    From: {req.get('src_ip','')}  UA: {req.get('user_agent','')[:60]}\n\n")

            # TLS tab
            t = self.tabs["TLS"]; t.delete('1.0', tk.END)
            tls = r.get('tls',{})
            t.insert(tk.END, f"TLS ANALYSIS\n{'='*60}\n  Handshakes: {tls.get('total_handshakes',0)}  Deprecated: {tls.get('deprecated_count',0)}\n\n")
            t.insert(tk.END, f"VERSIONS\n{'-'*40}\n")
            for v, c in tls.get('versions',{}).items():
                t.insert(tk.END, f"  {v:12s}  {c}\n")
            snis = tls.get('sni_list',[])
            if snis:
                t.insert(tk.END, f"\nSNI HOSTNAMES\n{'-'*40}\n")
                for sni in snis[:30]: t.insert(tk.END, f"  {sni}\n")

            # Threats tab
            t = self.tabs["Threats"]; t.delete('1.0', tk.END)
            anomalies = r.get('anomalies',[])
            t.insert(tk.END, f"ANOMALIES & THREATS ({len(anomalies)})\n{'='*60}\n\n")
            if anomalies:
                for a in anomalies:
                    t.insert(tk.END, f"  [{a['severity'].upper():8s}] [{a.get('category','')}]\n  {a['description']}\n\n")
            else:
                t.insert(tk.END, "  No anomalies detected — traffic appears clean.\n")

            # IOCs tab
            t = self.tabs["IOCs"]; t.delete('1.0', tk.END)
            iocs = r.get('iocs',[])
            t.insert(tk.END, f"INDICATORS OF COMPROMISE ({len(iocs)})\n{'='*60}\n\n")
            for ioc in iocs[:100]:
                t.insert(tk.END, f"  [{ioc['type']:20s}]  {ioc['value']}\n")

        def _open_pcap(self):
            p = filedialog.askopenfilename(title="Open PCAP File",
                filetypes=[("PCAP files","*.pcap *.pcapng *.cap"),("All","*.*")])
            if not p: return
            self._set_status("Analyzing..."); self.nb.select(0)
            def _go():
                try:
                    r = self.analyzer.analyze_file(p, log_cb=self._log)
                    self.results = r
                    self.root.after(0, lambda: self._update(r))
                    self._set_status(f"Done — {r.get('risk_level','?')} ({r.get('threat_score',0)}/100)")
                except Exception as e:
                    self._log(f"[!] ERROR: {e}")
                    self._set_status("Error — analysis failed")
                    self.root.after(0, lambda msg=str(e): messagebox.showerror("Analysis Failed", msg))
            threading.Thread(target=_go, daemon=True).start()

        def _gen_demo(self):
            p = filedialog.asksaveasfilename(title="Save Demo PCAP", defaultextension=".pcap",
                filetypes=[("PCAP","*.pcap")], initialfile="demo_capture.pcap")
            if not p: return
            self._log("[*] Generating demo PCAP...")
            DemoGenerator.generate(p)
            self._log(f"[+] Demo saved: {p}\n[*] Analyzing...")
            self._set_status("Analyzing demo...")
            def _go():
                try:
                    r = self.analyzer.analyze_file(p, log_cb=self._log)
                    self.results = r
                    self.root.after(0, lambda: self._update(r))
                    self._set_status(f"Demo analyzed — {r.get('risk_level','?')}")
                except Exception as e:
                    self._log(f"[!] ERROR: {e}")
                    self._set_status("Error — analysis failed")
                    self.root.after(0, lambda msg=str(e): messagebox.showerror("Analysis Failed", msg))
            threading.Thread(target=_go, daemon=True).start()

        def _export_html(self):
            if not self.results:
                messagebox.showwarning("No Results","Analyze a PCAP first."); return
            p = filedialog.asksaveasfilename(title="Save Report", defaultextension=".html",
                filetypes=[("HTML","*.html")], initialfile=f"pcap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
            if not p: return
            ReportGenerator.generate(self.results, self.results.get('file_info',{}), p)
            self._log(f"[+] Report: {p}"); messagebox.showinfo("Exported", f"Report saved:\n{p}")

        def _export_json(self):
            if not self.results:
                messagebox.showwarning("No Results","Analyze a PCAP first."); return
            p = filedialog.asksaveasfilename(title="Save JSON", defaultextension=".json",
                filetypes=[("JSON","*.json")], initialfile=f"pcap_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            if not p: return
            with open(p,'w') as f: json.dump(self.results, f, indent=2, default=str)
            self._log(f"[+] JSON: {p}")

        def _clear(self):
            self.results = None
            self.risk_lbl.configure(text="—", foreground=COLORS['accent'])
            self.risk_desc.configure(text="Awaiting analysis...")
            self.score_bar['value'] = 0; self.score_lbl.configure(text="0 / 100")
            for k in self.stat_labels: self.stat_labels[k].configure(text="—")
            for name, t in self.tabs.items():
                if name == "Log": continue
                t.delete('1.0', tk.END)
            self.tabs["Log"].config(state=tk.NORMAL); self.tabs["Log"].delete('1.0', tk.END)
            self.tabs["Log"].insert(tk.END, f"  {BRAND} — {TOOL_NAME} v{VERSION}\n  Cleared.\n\n")
            self.tabs["Log"].config(state=tk.DISABLED)
            self._set_status("Ready")

    root = tk.Tk(); App(root); root.mainloop()


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════


def _safe_print(text: str) -> None:
    """Windows cp1252-safe print."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode('ascii', errors='replace').decode('ascii'))


def _print_banner() -> None:
    """Print ASCII banner — safe on all terminals including Windows."""
    banner = (
        "\n+===========================================================================+\n"
        f"|  HFL PCAP ANALYZER v{VERSION} -- NBAD DETECTION ENGINE                   |\n"
        "|  HACKFORLAB -- Threat Intelligence Labs                                   |\n"
        "|  566-Port Intel | 80+ Detections | 60+ Attack Classes | MITRE ATT&CK     |\n"
        "+===========================================================================+\n"
    )
    _safe_print(banner)


def _resolve_targets(target_arg: str) -> list:
    """
    Resolve any user-supplied target to a list of PCAP file paths.
    Supports:
      - Single file:              /any/absolute/path/capture.pcap
      - Relative path:            capture.pcap  or  subdir/capture.pcap
      - Windows absolute path:    D:\\captures\\capture.pcap
      - Glob wildcard:            *.pcap  or  /path/*.pcap  or  D:\\path\\*.pcap
      - Directory (all PCAPs):    /path/to/pcap-folder/
      - Mixed platform paths work via Python's pathlib/glob
    Returns sorted list of existing file paths.
    """
    import glob as _glob

    if not target_arg:
        return []

    # Normalise Windows backslashes so glob works on all platforms
    normalised = target_arg.replace('\\', '/').replace('\\\\', '/')

    # Try glob expansion first (handles *.pcap and ? wildcards)
    expanded = _glob.glob(normalised, recursive=True)
    if not expanded:
        # Also try the original string in case OS already handles it
        expanded = _glob.glob(target_arg, recursive=True)

    if expanded:
        files = sorted(f for f in expanded if os.path.isfile(f))
        if files:
            return files

    # Plain existing file?
    if os.path.isfile(target_arg):
        return [target_arg]

    # Directory? Grab all PCAPs recursively
    target_path = Path(target_arg)
    if target_path.is_dir():
        files = []
        for ext in ('*.pcap', '*.pcapng', '*.cap', '*.pcap.gz', '*.pcapng.gz'):
            files.extend(str(p) for p in target_path.rglob(ext))
        return sorted(set(files))

    return []


def _merge_results(results_list: list) -> dict:
    """Merge analysis results from multiple PCAP files into one combined result."""
    if not results_list:
        return {}
    if len(results_list) == 1:
        return results_list[0]

    merged = {
        'summary': {
            'total_packets': 0, 'total_bytes': 0, 'total_bytes_human': '',
            'duration_seconds': 0, 'duration_human': '', 'unique_ips': 0,
            'unique_macs': 0, 'external_ips': 0, 'internal_ips': 0,
            'total_flows': 0, 'packets_per_second': 0, 'bandwidth_human': '',
            'first_timestamp': 0, 'last_timestamp': 0,
        },
        'protocols': Counter(), 'top_talkers_src': Counter(),
        'top_talkers_dst': Counter(), 'top_ports': Counter(), 'top_flows': [],
        'dns': {'total_queries': 0, 'unique_domains': 0, 'top_domains': Counter(),
                'query_types': Counter(), 'domains': []},
        'http': {'total_requests': 0, 'methods': Counter(),
                 'hosts': Counter(), 'user_agents': Counter(), 'requests': []},
        'tls': {'total_handshakes': 0, 'versions': Counter(),
                'sni_list': [], 'deprecated_count': 0},
        'anomalies': [], 'anomaly_summary': Counter(),
        'threat_score': 0, 'risk_level': 'CLEAN',
        'iocs': [], 'ttl_distribution': Counter(),
        'file_info': {'filename': f'Batch ({len(results_list)} files)', 'size': 0, 'size_human': ''},
        '_batch_files': [],
    }

    seen_iocs: set = set()
    all_scores: list = []

    for r in results_list:
        s = r.get('summary', {})
        for field in ('total_packets', 'total_bytes', 'total_flows', 'unique_ips',
                      'external_ips', 'internal_ips'):
            merged['summary'][field] += s.get(field, 0)

        for k, v in r.get('protocols', {}).items():
            merged['protocols'][k] += v
        for k, v in r.get('top_talkers_src', {}).items():
            merged['top_talkers_src'][k] += v
        for k, v in r.get('top_talkers_dst', {}).items():
            merged['top_talkers_dst'][k] += v
        for k, v in r.get('top_ports', {}).items():
            merged['top_ports'][k] += v
        for k, v in r.get('dns', {}).get('top_domains', {}).items():
            merged['dns']['top_domains'][k] += v
        merged['dns']['total_queries'] += r.get('dns', {}).get('total_queries', 0)
        merged['http']['total_requests'] += r.get('http', {}).get('total_requests', 0)
        merged['tls']['total_handshakes'] += r.get('tls', {}).get('total_handshakes', 0)
        merged['tls']['deprecated_count']  += r.get('tls', {}).get('deprecated_count', 0)

        merged['anomalies'].extend(r.get('anomalies', []))
        for k, v in r.get('anomaly_summary', {}).items():
            merged['anomaly_summary'][k] += v

        all_scores.append(r.get('threat_score', 0))

        for ioc in r.get('iocs', []):
            key = f"{ioc['type']}:{ioc['value']}"
            if key not in seen_iocs:
                seen_iocs.add(key)
                merged['iocs'].append(ioc)

        fi = r.get('file_info', {})
        merged['_batch_files'].append({
            'filename': fi.get('filename', '?'),
            'size_human': fi.get('size_human', ''),
            'risk':       r.get('risk_level', 'CLEAN'),
            'score':      r.get('threat_score', 0),
            'anomalies':  len(r.get('anomalies', [])),
        })

    score = min(max(all_scores) if all_scores else 0, 100)
    merged['threat_score'] = score
    if score >= 50:   merged['risk_level'] = 'CRITICAL'
    elif score >= 30: merged['risk_level'] = 'HIGH'
    elif score >= 15: merged['risk_level'] = 'MEDIUM'
    elif score > 0:   merged['risk_level'] = 'LOW'

    merged['summary']['total_bytes_human'] = _human_bytes(merged['summary']['total_bytes'])
    merged['protocols']         = dict(merged['protocols'].most_common())
    merged['top_talkers_src']   = dict(merged['top_talkers_src'].most_common(15))
    merged['top_talkers_dst']   = dict(merged['top_talkers_dst'].most_common(15))
    merged['top_ports']         = dict(merged['top_ports'].most_common(20))
    merged['dns']['top_domains'] = dict(merged['dns']['top_domains'].most_common(20))
    merged['anomaly_summary']   = dict(merged['anomaly_summary'])
    return merged


def main():
    # ── Windows UTF-8 fix ────────────────────────────────────────────────────
    if sys.platform == 'win32':
        try:
            import io as _io
            sys.stdout = _io.TextIOWrapper(
                sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
            sys.stderr = _io.TextIOWrapper(
                sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)
            os.system('chcp 65001 >nul 2>&1')
        except Exception:
            pass

    if len(sys.argv) == 1:
        _print_banner()
        _safe_print("[*] No arguments — launching GUI...\n")
        launch_gui()
        return

    _print_banner()

    parser = argparse.ArgumentParser(
        prog='HFL_PCAP_Analyzer.py',
        description=f'{TOOL_NAME} v{VERSION} -- HACKFORLAB',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Examples:\n"
            "    python3 HFL_PCAP_Analyzer.py capture.pcap\n"
            "    python3 HFL_PCAP_Analyzer.py /any/absolute/path/capture.pcap\n"
            "    python3 HFL_PCAP_Analyzer.py /path/to/pcaps/\n"
            "    python3 HFL_PCAP_Analyzer.py *.pcap\n"
            "    python3 HFL_PCAP_Analyzer.py capture.pcap -r my_report.html\n"
            "    python3 HFL_PCAP_Analyzer.py capture.pcap --json\n"
            "    python3 HFL_PCAP_Analyzer.py --demo\n\n"
            "  Reports: auto-saved to REPORT/HFL_YYYYMMDD_HHMMSS_<name>.html\n"
            "  HACKFORLAB -- All Rights Reserved"
        ),
    )
    parser.add_argument('target', nargs='?',
        help='PCAP file, directory, or glob pattern (any path format)')
    parser.add_argument('--report', '-r', default=None,
        help='Override output HTML report path')
    parser.add_argument('--json', '-j', action='store_true',
        help='Print JSON analysis to stdout')
    parser.add_argument('--demo', '-d', action='store_true',
        help='Generate a demo PCAP and run analysis')
    parser.add_argument('--no-report', action='store_true',
        help='Skip HTML report generation')
    parser.add_argument('--gui', '-g', action='store_true',
        help='Force GUI mode')
    args = parser.parse_args()

    if args.gui:
        launch_gui()
        return

    analyzer = PacketCaptureAnalyzer()
    target_files: list = []

    # ── DEMO MODE ────────────────────────────────────────────────────────────
    if args.demo:
        demo_dir  = _report_dir()  # Put demo pcap in REPORT/ too
        demo_path = os.path.join(demo_dir, 'demo_capture.pcap')
        _safe_print("[*] Generating demo PCAP...\n")
        DemoGenerator.generate(demo_path)
        _safe_print(f"[+] Demo PCAP: {demo_path}\n")
        results      = analyzer.analyze_file(demo_path)
        target_files = [demo_path]

    # ── FILE / GLOB / DIRECTORY MODE ─────────────────────────────────────────
    elif args.target:
        target_files = _resolve_targets(args.target)

        if not target_files:
            _safe_print(f"[!] No PCAP files found for: {args.target}")
            _safe_print("    Accepted formats: file.pcap | /any/path/file.pcap | /dir/ | *.pcap")
            sys.exit(1)

        _safe_print(f"[*] Found {len(target_files)} file(s)\n")

        if len(target_files) == 1:
            results = analyzer.analyze_file(target_files[0])
        else:
            results_list = []
            for i, fp in enumerate(target_files, 1):
                _safe_print(f"[{i:>3}/{len(target_files)}] {os.path.basename(fp)}")
                try:
                    results_list.append(analyzer.analyze_file(fp))
                except Exception as e:
                    _safe_print(f"        [!] SKIP: {e}")
            if not results_list:
                _safe_print("[!] All files failed to parse.")
                sys.exit(1)
            _safe_print(f"\n[*] Merging {len(results_list)} results...\n")
            results = _merge_results(results_list)

    else:
        parser.print_help()
        sys.exit(0)

    # ── JSON OUTPUT ──────────────────────────────────────────────────────────
    if args.json:
        _safe_print("\n" + json.dumps(results, indent=2, default=str))

    # ── HTML REPORT ──────────────────────────────────────────────────────────
    if not args.no_report:
        # Determine report path:
        #   1. --report <path>  if user explicitly provided one
        #   2. REPORT/HFL_DATETIME_PCAPNAME.html  (default)
        if args.report:
            rp = args.report
            os.makedirs(os.path.dirname(os.path.abspath(rp)), exist_ok=True)
        else:
            pcap_name = target_files[0] if target_files else 'batch'
            rp = _report_filename(pcap_name)

        ReportGenerator.generate(results, results.get('file_info', {}), rp)
        _safe_print(f"\n[+] Report saved: {rp}")

    # ── SUMMARY ──────────────────────────────────────────────────────────────
    s   = results.get('summary', {})
    sep = "=" * 73
    _safe_print(f"\n{sep}")
    _safe_print(f"  ANALYSIS COMPLETE")
    if len(target_files) > 1:
        _safe_print(f"  Files analyzed : {len(target_files)}")
    _safe_print(f"  Packets        : {s.get('total_packets', 0):,}")
    _safe_print(f"  Data volume    : {s.get('total_bytes_human', '0 B')}")
    _safe_print(f"  Duration       : {s.get('duration_human', '0:00:00')}")
    _safe_print(f"  Unique IPs     : {s.get('unique_ips', 0)}  ({s.get('external_ips', 0)} external)")
    _safe_print(f"  Flows          : {s.get('total_flows', 0)}")
    _safe_print(f"  Risk Level     : {results.get('risk_level', 'CLEAN')} ({results.get('threat_score', 0)}/100)")
    _safe_print(f"  Anomalies      : {len(results.get('anomalies', []))}")
    _safe_print(f"  IOCs           : {len(results.get('iocs', []))}")

    asummary = results.get('anomaly_summary', {})
    if asummary:
        _safe_print(f"\n  Anomaly Breakdown:")
        for cat, count in sorted(asummary.items(), key=lambda x: -x[1]):
            bar = '#' * min(count, 30)
            _safe_print(f"    {cat:<26} {count:>4}  {bar}")

    batch = results.get('_batch_files', [])
    if batch:
        _safe_print(f"\n  Per-File Summary:")
        for bf in batch:
            _safe_print(f"    [{bf['risk']:<8}] {bf['score']:>3}/100  "
                        f"{bf['anomalies']:>4} anomalies  {bf['filename']}")

    _safe_print(f"{sep}\n")


if __name__ == '__main__':
    main()