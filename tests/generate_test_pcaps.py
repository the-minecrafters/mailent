#!/usr/bin/env python3
"""
Generates a wide variety of edge-case, adversarial, corrupted, and multi-protocol PCAP files
to stress-test Mailent's packet parsing, protocol reconstruction, and validation pipelines.
"""

import os
import struct
import socket

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures", "pcap_edge")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def checksum(data: bytes) -> int:
    """Standard internet checksum (RFC 1071)."""
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while (s >> 16) > 0:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def build_ipv4_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      tcp_flags: int, seq: int, ack: int, payload: bytes) -> bytes:
    """Build Ethernet + IPv4 + TCP packet."""
    eth = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + struct.pack("!H", 0x0800)
    
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    
    ip_ihl_ver = 0x45
    ip_tos = 0
    ip_id = 54321
    ip_frag_off = 0x4000 # DF
    ip_ttl = 64
    ip_proto = 6 # TCP
    
    tcp_hdr_len = 20
    ip_total_len = 20 + tcp_hdr_len + len(payload)
    
    ip_hdr_no_cksum = struct.pack("!BBHHHBBH4s4s",
        ip_ihl_ver, ip_tos, ip_total_len, ip_id, ip_frag_off,
        ip_ttl, ip_proto, 0, src_bytes, dst_bytes)
    ip_cksum = checksum(ip_hdr_no_cksum)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        ip_ihl_ver, ip_tos, ip_total_len, ip_id, ip_frag_off,
        ip_ttl, ip_proto, ip_cksum, src_bytes, dst_bytes)
    
    data_offset = (tcp_hdr_len // 4) << 4
    window = 65535
    urgent = 0
    
    pseudo_hdr = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, 6, tcp_hdr_len + len(payload))
    tcp_no_cksum = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset, tcp_flags, window, 0, urgent) + payload
    tcp_cksum = checksum(pseudo_hdr + tcp_no_cksum)
    tcp_hdr = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset, tcp_flags, window, tcp_cksum, urgent)
    
    return eth + ip_hdr + tcp_hdr + payload

def build_ipv6_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      tcp_flags: int, seq: int, ack: int, payload: bytes) -> bytes:
    """Build Ethernet + IPv6 + TCP packet."""
    eth = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + struct.pack("!H", 0x86DD)
    src_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
    dst_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
    
    tcp_hdr_len = 20
    payload_len = tcp_hdr_len + len(payload)
    ipv6_hdr = struct.pack("!IHBB16s16s", 0x60000000, payload_len, 6, 64, src_bytes, dst_bytes)
    
    data_offset = (tcp_hdr_len // 4) << 4
    window = 65535
    urgent = 0
    
    pseudo_hdr = src_bytes + dst_bytes + struct.pack("!IBBB", payload_len, 0, 0, 6)
    tcp_no_cksum = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset, tcp_flags, window, 0, urgent) + payload
    tcp_cksum = checksum(pseudo_hdr + tcp_no_cksum)
    tcp_hdr = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset, tcp_flags, window, tcp_cksum, urgent)
    
    return eth + ipv6_hdr + tcp_hdr + payload

def build_vlan_packet(vlan_id: int, inner_eth_pkt: bytes) -> bytes:
    """Wrap standard Ethernet packet in an 802.1Q VLAN tag."""
    dst_mac = inner_eth_pkt[:6]
    src_mac = inner_eth_pkt[6:12]
    ethertype = inner_eth_pkt[12:14]
    tpid = struct.pack("!H", 0x8100)
    tci = struct.pack("!H", vlan_id & 0x0FFF)
    return dst_mac + src_mac + tpid + tci + ethertype + inner_eth_pkt[14:]

class TcpSession:
    def __init__(self, client_ip: str, server_ip: str, client_port: int, server_port: int,
                 init_client_seq: int = 1000, init_server_seq: int = 2000):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.c_seq = init_client_seq
        self.s_seq = init_server_seq
        self.packets = []
        
        # 3-Way Handshake
        # SYN (client)
        self.packets.append(build_ipv4_packet(client_ip, server_ip, client_port, server_port, 0x02, self.c_seq, 0, b""))
        self.c_seq += 1
        # SYN-ACK (server)
        self.packets.append(build_ipv4_packet(server_ip, client_ip, server_port, client_port, 0x12, self.s_seq, self.c_seq, b""))
        self.s_seq += 1
        # ACK (client)
        self.packets.append(build_ipv4_packet(client_ip, server_ip, client_port, server_port, 0x10, self.c_seq, self.s_seq, b""))

    def client_send(self, payload: bytes):
        pkt = build_ipv4_packet(self.client_ip, self.server_ip, self.client_port, self.server_port, 0x18, self.c_seq, self.s_seq, payload)
        self.packets.append(pkt)
        self.c_seq += len(payload)
        ack = build_ipv4_packet(self.server_ip, self.client_ip, self.server_port, self.client_port, 0x10, self.s_seq, self.c_seq, b"")
        self.packets.append(ack)

    def server_send(self, payload: bytes):
        pkt = build_ipv4_packet(self.server_ip, self.client_ip, self.server_port, self.client_port, 0x18, self.s_seq, self.c_seq, payload)
        self.packets.append(pkt)
        self.s_seq += len(payload)
        ack = build_ipv4_packet(self.client_ip, self.server_ip, self.client_port, self.server_port, 0x10, self.c_seq, self.s_seq, b"")
        self.packets.append(ack)

    def rst_from_server(self):
        pkt = build_ipv4_packet(self.server_ip, self.client_ip, self.server_port, self.client_port, 0x04, self.s_seq, 0, b"")
        self.packets.append(pkt)

class TcpSessionIpv6:
    def __init__(self, client_ip: str, server_ip: str, client_port: int, server_port: int,
                 init_client_seq: int = 1000, init_server_seq: int = 2000):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.c_seq = init_client_seq
        self.s_seq = init_server_seq
        self.packets = []
        
        # 3-Way Handshake
        self.packets.append(build_ipv6_packet(client_ip, server_ip, client_port, server_port, 0x02, self.c_seq, 0, b""))
        self.c_seq += 1
        self.packets.append(build_ipv6_packet(server_ip, client_ip, server_port, client_port, 0x12, self.s_seq, self.c_seq, b""))
        self.s_seq += 1
        self.packets.append(build_ipv6_packet(client_ip, server_ip, client_port, server_port, 0x10, self.c_seq, self.s_seq, b""))

    def client_send(self, payload: bytes):
        pkt = build_ipv6_packet(self.client_ip, self.server_ip, self.client_port, self.server_port, 0x18, self.c_seq, self.s_seq, payload)
        self.packets.append(pkt)
        self.c_seq += len(payload)
        ack = build_ipv6_packet(self.server_ip, self.client_ip, self.server_port, self.client_port, 0x10, self.s_seq, self.c_seq, b"")
        self.packets.append(ack)

    def server_send(self, payload: bytes):
        pkt = build_ipv6_packet(self.server_ip, self.client_ip, self.server_port, self.client_port, 0x18, self.s_seq, self.c_seq, payload)
        self.packets.append(pkt)
        self.s_seq += len(payload)
        ack = build_ipv6_packet(self.client_ip, self.server_ip, self.client_port, self.server_port, 0x10, self.c_seq, self.s_seq, b"")
        self.packets.append(ack)

def write_pcap(path: str, packets: list[bytes], magic=0xa1b2c3d4, snaplen=65535, endian="<"):
    """Write pcap file with given packets."""
    endian_flag = "<" if endian == "<" else ">"
    hdr = struct.pack(f"{endian_flag}IHHIIII", magic, 2, 4, 0, 0, snaplen, 1)
    with open(path, "wb") as f:
        f.write(hdr)
        ts_sec = 1789992000
        for i, pkt in enumerate(packets):
            ts_usec = i * 1000
            caplen = len(pkt)
            origlen = len(pkt)
            pkthdr = struct.pack(f"{endian_flag}IIII", ts_sec, ts_usec, caplen, origlen)
            f.write(pkthdr)
            f.write(pkt)

def gen_all():
    print("Generating edge-case PCAPs in:", OUTPUT_DIR)
    
    # 1. Nanosecond little-endian and big-endian
    write_pcap(os.path.join(OUTPUT_DIR, "nanosecond_le.pcap"), [], magic=0xa1b23c4d, endian="<")
    write_pcap(os.path.join(OUTPUT_DIR, "nanosecond_be.pcap"), [], magic=0xa1b23c4d, endian=">")
    write_pcap(os.path.join(OUTPUT_DIR, "microsecond_be.pcap"), [], magic=0xa1b2c3d4, endian=">")
    
    # 2. Corrupted packet header (caplen > origlen and caplen > remaining file size)
    hdr = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    bad_pkthdr = struct.pack("<IIII", 1789992000, 1000, 50000, 100)
    with open(os.path.join(OUTPUT_DIR, "corrupted_packet_len.pcap"), "wb") as f:
        f.write(hdr)
        f.write(bad_pkthdr)
        f.write(b"only a few bytes of payload here")

    # 3. Truncated PCAP global header (only 14 bytes)
    with open(os.path.join(OUTPUT_DIR, "truncated_header.pcap"), "wb") as f:
        f.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00")

    # 4. Zero snaplen
    write_pcap(os.path.join(OUTPUT_DIR, "zero_snaplen.pcap"), [], snaplen=0)

    # 5. SMTP session with huge greeting banner (DoS attempt / buffer limit)
    client_ip, server_ip = "192.168.1.50", "192.168.1.25"
    cp, sp = 54321, 25
    s5 = TcpSession(client_ip, server_ip, cp, sp)
    banner = b"220 " + (b"A" * 32000) + b"\r\n"
    s5.server_send(banner)
    s5.client_send(b"QUIT\r\n")
    s5.server_send(b"221 2.0.0 Bye\r\n")
    write_pcap(os.path.join(OUTPUT_DIR, "smtp_huge_greeting.pcap"), s5.packets)

    # 6. SMTP STARTTLS command injection (pipelining STARTTLS with plaintext commands)
    s6 = TcpSession(client_ip, server_ip, cp, sp)
    s6.server_send(b"220 mail.mailent.test ESMTP Service Ready\r\n")
    s6.client_send(b"EHLO mail.example.com\r\n")
    s6.server_send(b"250-server.mailent.test\r\n250 STARTTLS\r\n")
    s6.client_send(b"STARTTLS\r\nRSET\r\nMAIL FROM:<evil@attacker.com>\r\n")
    write_pcap(os.path.join(OUTPUT_DIR, "smtp_starttls_injection.pcap"), s6.packets)

    # 7. SMTP STARTTLS 454 failure and plaintext fallback
    s7 = TcpSession(client_ip, server_ip, cp, sp)
    s7.server_send(b"220 mail.mailent.test ESMTP\r\n")
    s7.client_send(b"EHLO client.test\r\n")
    s7.server_send(b"250-mail.mailent.test\r\n250-STARTTLS\r\n250 OK\r\n")
    s7.client_send(b"STARTTLS\r\n")
    s7.server_send(b"454 TLS not available\r\n")
    s7.client_send(b"AUTH LOGIN\r\n")
    s7.server_send(b"334 VXNlcm5hbWU6\r\n")
    s7.client_send(b"dXNlcg==\r\n")
    s7.server_send(b"334 UGFzc3dvcmQ6\r\n")
    s7.client_send(b"cGFzczEyMw==\r\n")
    s7.server_send(b"235 2.7.0 Authentication successful\r\n")
    s7.client_send(b"QUIT\r\n")
    s7.server_send(b"221 Bye\r\n")
    write_pcap(os.path.join(OUTPUT_DIR, "smtp_downgrade_auth_exposed.pcap"), s7.packets)

    # 8. Non-standard port SMTP (port 2525)
    s8 = TcpSession(client_ip, server_ip, 54322, 2525)
    s8.server_send(b"220 mail.altport.test ESMTP Service Ready\r\n")
    s8.client_send(b"EHLO client.test\r\n")
    s8.server_send(b"250-mail.altport.test\r\n250-STARTTLS\r\n250 OK\r\n")
    write_pcap(os.path.join(OUTPUT_DIR, "smtp_port_2525.pcap"), s8.packets)

    # 9. POP3 STLS negative response followed by plaintext auth
    s9 = TcpSession(client_ip, server_ip, 55110, 110)
    s9.server_send(b"+OK Dovecot ready.\r\n")
    s9.client_send(b"STLS\r\n")
    s9.server_send(b"-ERR TLS not available\r\n")
    s9.client_send(b"USER admin\r\n")
    s9.server_send(b"+OK User accepted\r\n")
    s9.client_send(b"PASS secret123\r\n")
    s9.server_send(b"+OK Logged in\r\n")
    write_pcap(os.path.join(OUTPUT_DIR, "pop3_stls_rejected.pcap"), s9.packets)

    # 10. Malformed TLS record on port 465 (SMTPS)
    s10 = TcpSession(client_ip, server_ip, 55465, 465)
    bad_tls = struct.pack("!BBHH", 0xFE, 0x03, 0x03, 16) + (b"\xAA" * 16)
    s10.client_send(bad_tls)
    write_pcap(os.path.join(OUTPUT_DIR, "smtps_malformed_tls.pcap"), s10.packets)

    # 11. Multi-session mixed protocol PCAP (SMTP + POP3 + DNS)
    dns_pkt = bytes.fromhex("00112233445566778899aabb0800") + \
              struct.pack("!BBHHHBBH4s4s", 0x45, 0, 48, 1234, 0, 64, 17, 0, socket.inet_aton("192.168.1.50"), socket.inet_aton("1.1.1.1")) + \
              struct.pack("!HHHH", 53535, 53, 28, 0) + b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x00\x00\x01\x00\x01"
    write_pcap(os.path.join(OUTPUT_DIR, "multi_protocol_mixed.pcap"),
               [dns_pkt] + s7.packets[:6] + s9.packets[:4])

    # 12. IPv6 SMTP session with STARTTLS
    s12 = TcpSessionIpv6("2001:db8::1", "2001:db8::2", 51234, 25)
    s12.server_send(b"220 mail.ipv6.test ESMTP\r\n")
    s12.client_send(b"EHLO client.ipv6.test\r\n")
    s12.server_send(b"250-mail.ipv6.test\r\n250-STARTTLS\r\n250 OK\r\n")
    s12.client_send(b"STARTTLS\r\n")
    s12.server_send(b"220 2.0.0 Ready to start TLS\r\n")
    write_pcap(os.path.join(OUTPUT_DIR, "ipv6_smtp.pcap"), s12.packets)

    # 13. 802.1Q VLAN Tagged SMTP session
    s13 = TcpSession("10.0.1.10", "10.0.1.25", 52100, 25)
    s13.server_send(b"220 vlan-mail.corp.test ESMTP\r\n")
    s13.client_send(b"EHLO vlan-client.corp.test\r\n")
    s13.server_send(b"250-vlan-mail.corp.test\r\n250-STARTTLS\r\n250 OK\r\n")
    s13.client_send(b"QUIT\r\n")
    vlan_pkts = [build_vlan_packet(100, p) for p in s13.packets]
    write_pcap(os.path.join(OUTPUT_DIR, "vlan_tagged_smtp.pcap"), vlan_pkts)

    # 14. TCP Out-of-Order Packets
    s14 = TcpSession("192.168.1.50", "192.168.1.25", 54323, 25)
    p1 = build_ipv4_packet("192.168.1.25", "192.168.1.50", 25, 54323, 0x18, s14.s_seq, s14.c_seq, b"220 mail.")
    p2 = build_ipv4_packet("192.168.1.25", "192.168.1.50", 25, 54323, 0x18, s14.s_seq + 9, s14.c_seq, b"test ESMTP\r\n")
    s14_pkts = s14.packets + [p2, p1]
    write_pcap(os.path.join(OUTPUT_DIR, "tcp_out_of_order.pcap"), s14_pkts)

    # 15. Non-mail HTTP traffic on port 25
    s15 = TcpSession("192.168.1.50", "192.168.1.25", 54324, 25)
    s15.client_send(b"GET /health HTTP/1.1\r\nHost: mail.test\r\nUser-Agent: curl/7.88\r\n\r\n")
    s15.server_send(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    write_pcap(os.path.join(OUTPUT_DIR, "non_mail_http_on_port_25.pcap"), s15.packets)

    # 16. Non-mail SSH banner on port 25
    s16 = TcpSession("192.168.1.50", "192.168.1.25", 54325, 25)
    s16.server_send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    s16.client_send(b"SSH-2.0-OpenSSH_9.0\r\n")
    write_pcap(os.path.join(OUTPUT_DIR, "non_mail_ssh_on_port_25.pcap"), s16.packets)

    # 17. IMAP unencrypted plaintext LOGIN
    s17 = TcpSession("192.168.1.50", "192.168.1.25", 54143, 143)
    s17.server_send(b"* OK Dovecot ready.\r\n")
    s17.client_send(b"a001 CAPABILITY\r\n")
    s17.server_send(b"* CAPABILITY IMAP4rev1 SASL-IR AUTH=PLAIN\r\na001 OK Pre-login capabilities listed, post-login can differ\r\n")
    s17.client_send(b"a002 LOGIN user secret_pass\r\n")
    s17.server_send(b"a002 OK Logged in\r\n")
    write_pcap(os.path.join(OUTPUT_DIR, "imap_unencrypted_login.pcap"), s17.packets)

    # 18. SMTP mid-handshake sudden TCP RST
    s18 = TcpSession("192.168.1.50", "192.168.1.25", 54326, 25)
    s18.server_send(b"220 mail.mailent.test ESMTP\r\n")
    s18.client_send(b"EHLO client.test\r\n")
    s18.server_send(b"250-mail.mailent.test\r\n250 STARTTLS\r\n")
    s18.client_send(b"STARTTLS\r\n")
    s18.server_send(b"220 Ready to start TLS\r\n")
    s18.rst_from_server()
    write_pcap(os.path.join(OUTPUT_DIR, "smtp_mid_handshake_rst.pcap"), s18.packets)

    print("Successfully generated all edge-case PCAPs.")

if __name__ == "__main__":
    gen_all()
