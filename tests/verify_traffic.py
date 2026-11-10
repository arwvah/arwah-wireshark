#!/usr/bin/env python3
"""Behavioral integration tests against real Wireshark dissectors (Scapy fixtures)."""
import argparse
import json
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time

from scapy.all import ARP, DNS, DNSQR, Dot1Q, Ether, ICMP, IP, IPv6, Raw, TCP, UDP, wrpcap
from scapy.layers.inet6 import ICMPv6EchoRequest

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "samples" / "traffic-demo.pcap"


def fixture():
    packets, expected, groups = [], {}, {}
    clock = 1700000000
    source_serial = 45000

    def add(name, batch, rules=None):
        nonlocal clock
        groups[name] = []
        for offset, packet in enumerate(batch):
            packet.time = clock + offset / 1000
            packets.append(packet)
            number = len(packets)
            groups[name].append(number)
            for rule in (rules(offset) if callable(rules) else rules or []):
                expected.setdefault(rule, set()).add(number)
        clock += 100

    def ipv4():
        return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.0.2.1", dst="192.0.2.2")

    def tcp(port=80, flags="PA", payload=b"", source=None):
        nonlocal source_serial
        if source is None:
            source_serial += 1
            source = 42000 if flags != "PA" else source_serial
        return ipv4() / TCP(sport=source, dport=port, flags=flags, seq=100) / Raw(payload)

    def http(uri="/", authorization=""):
        return tcp(payload=f"GET {uri} HTTP/1.1\r\nHost: example.test\r\n{authorization}\r\n".encode())

    add("normal", [http(), ipv4()/UDP(sport=42000,dport=9999)/Raw(b"ordinary"),
                   ipv4()/ICMP(), ipv4()/UDP(sport=42000,dport=53)/DNS(qd=DNSQR(qname="example.test")),
                   tcp(flags="S"), tcp(flags="A")])
    add("null", [tcp(flags=0)], ["tcp.null"])
    add("xmas", [tcp(flags="FPU")], ["tcp.xmas"])
    add("conflicting", [tcp(flags="SF"),tcp(flags="SR")], ["tcp.conflicting_flags"])
    add("scan", [tcp(port=10000+i,flags="S") for i in range(21)],
        lambda i: ["tcp.port_scan"] if i >= 19 else [])
    add("sweep", [Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src="192.0.2.1",dst=f"198.51.100.{i+1}")/TCP(sport=42000,dport=80,flags="S") for i in range(20)],
        lambda i: ["tcp.host_sweep"] if i == 19 else [])
    add("syn", [tcp(flags="S",source=42000+i) for i in range(101)],
        lambda i: ["tcp.syn_burst"] if i >= 99 else [])
    add("syn_retries", [tcp(flags="S") for _ in range(110)])
    add("udp", [ipv4()/UDP(sport=42000,dport=9999)/Raw(b"fixture") for _ in range(201)],
        lambda i: ["udp.burst"] if i >= 199 else [])
    add("icmp", [ipv4()/ICMP(seq=i) for i in range(51)],
        lambda i: ["icmp.echo_burst"] if i >= 49 else [])
    add("large_echo", [ipv4()/ICMP()/Raw(b"a"*1400)], ["icmp.large_echo"])
    add("ipv6_scan", [Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IPv6(src="2001:db8::1",dst="2001:db8::2")/TCP(sport=42000,dport=10000+i,flags="S") for i in range(20)],
        lambda i: ["tcp.port_scan"] if i == 19 else [])
    add("ipv6_echo", [Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IPv6(src="2001:db8::1",dst="2001:db8::2")/ICMPv6EchoRequest(seq=i) for i in range(50)],
        lambda i: ["icmp.echo_burst"] if i == 49 else [])
    add("dns_rate", [ipv4()/UDP(sport=42000,dport=53)/DNS(id=i,qd=DNSQR(qname="example.test")) for i in range(100)],
        lambda i: ["dns.query_burst"] if i == 99 else [])
    add("dns_nx", [ipv4()/UDP(sport=53,dport=42000)/DNS(id=i,qr=1,rcode=3,qd=DNSQR(qname="missing.test")) for i in range(20)],
        lambda i: ["dns.nxdomain"] + (["dns.nxdomain_burst"] if i == 19 else []))
    add("dns_long", [ipv4()/UDP(sport=42000,dport=53)/DNS(qd=DNSQR(qname="a"*40+"."+"b"*30+".test"))], ["dns.long_name"])
    add("dns_encoded", [ipv4()/UDP(sport=42000,dport=53)/DNS(qd=DNSQR(qname="abcdefghijklmnopqrstuvwxyz0123456789.test"))], ["dns.encoded_label"])
    add("dns_txt", [ipv4()/UDP(sport=42000,dport=53)/DNS(qd=DNSQR(qname="example.test",qtype=16))], ["dns.txt"])
    add("basic", [http(authorization="Authorization: Basic ZGVtbzpkZW1v\r\n")], ["http.basic_cleartext"])
    add("ftp", [tcp(port=21,payload=b"PASS demo-only\r\n")], ["ftp.password_cleartext"])
    add("smtp", [tcp(port=25,payload=b"AUTH PLAIN ZGVtby1vbmx5\r\n")], ["smtp.auth_cleartext"])
    add("telnet", [tcp(port=23,payload=b"\xff\xfb\x01")], ["telnet.cleartext"])
    add("traversal", [http("/../../etc/hosts"),http("/%252e%252e%252fetc/hosts")], ["http.path_traversal"])
    add("sql", [http("/?q=union%20select%201")], ["http.sql_pattern"])
    add("script", [http("/?q=%3Cscript%3E")], ["http.script_pattern"])
    add("auth_fail", [tcp(port=42000+i,source=80,payload=b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n") for i in range(10)],
        lambda i: ["http.auth_failure_burst"] if i == 9 else [])
    # Syntactically valid TLS 1.0 ServerHello, not a record-version shortcut.
    hello = b"\x03\x01" + bytes(32) + b"\x00\x00\x2f\x00"
    handshake = b"\x02" + len(hello).to_bytes(3,"big") + hello
    tls = b"\x16\x03\x01" + len(handshake).to_bytes(2,"big") + handshake
    add("tls", [tcp(port=42000,source=443,payload=tls)], ["tls.legacy_version"])
    add("arp", [Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/ARP(op=2,psrc="192.0.2.254",hwsrc=mac) for mac in ("02:00:00:00:00:01","02:00:00:00:00:02")],
        lambda i: ["arp.mapping_change"] if i == 1 else [])
    add("arp_vlan", [Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/Dot1Q(vlan=i+1)/ARP(op=2,psrc="192.0.2.254",hwsrc=f"02:00:00:00:00:0{i+1}") for i in range(2)])
    # Half a scan before and half after expiry must not combine.
    add("expired_a", [tcp(port=11000+i,flags="S") for i in range(10)])
    add("expired_b", [tcp(port=12000+i,flags="S") for i in range(10)])
    wrpcap(str(CAPTURE), packets)
    return expected, groups


def command(installed):
    return ["tshark", "-n"] + ([] if installed else ["-X", f"lua_script:{ROOT/'arwah_traffic.lua'}"])


def read(installed, extra=()):
    run = subprocess.run(command(installed)+["-r",str(CAPTURE),*extra,"-T","fields",
        "-e","frame.number","-e","arwah.rule","-e","arwah.limited","-e","arwah.severity",
        "-e","_ws.lua.error","-e","_ws.col.Info"], text=True,capture_output=True,check=True)
    assert "Lua" not in run.stderr, run.stderr
    rows = {}
    for line in run.stdout.splitlines():
        number,rules,limited,severity,error,info = line.split("\t",5)
        assert not error, (number,error,info)
        limited = {"False": "0", "True": "1"}.get(limited, limited)
        rows[int(number)] = (set(rules.split(",")) if rules else set(),limited,severity,info)
    return rows


def live(installed):
    """Capture only self-generated localhost UDP; no external traffic."""
    receiver = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1",0))
    port = receiver.getsockname()[1]
    with tempfile.TemporaryFile(mode="w+") as output:
        process = subprocess.Popen(command(installed)+["-l","-i","lo","-f",f"udp dst port {port}",
            "-a","duration:3","-o","arwah.udp_rate:10","-Y",'arwah.rule == "udp.burst"',
            "-T","fields","-e","arwah.rule"],stdout=output,stderr=subprocess.PIPE,text=True)
        try:
            ready = False
            deadline = time.monotonic()+6
            while time.monotonic()<deadline and process.poll() is None:
                if select.select([process.stderr],[],[],0.1)[0]:
                    line = process.stderr.readline()
                    if "Capturing on" in line:
                        ready=True
                        break
            assert ready,"Live capture did not start"
            time.sleep(0.4)
            sender = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            for _ in range(20):
                sender.sendto(b"arwah-local-test",("127.0.0.1",port))
                time.sleep(0.01)
            sender.close()
            _, errors = process.communicate(timeout=8)
            output.seek(0)
            alerts = output.read().splitlines()
            assert process.returncode == 0 and len(alerts)>=10,(process.returncode,errors,alerts)
            print(f"PASS: live loopback capture, {len(alerts)} UDP burst flags")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            receiver.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--installed",action="store_true")
    parser.add_argument("--live",action="store_true")
    args=parser.parse_args()
    expected, groups=fixture()
    first=read(args.installed)
    second=read(args.installed,["-2"])
    assert {n:r[:3] for n,r in first.items()} == {n:r[:3] for n,r in second.items()}, "Revisit changed indicators"
    actual={}
    for number,(rules,limited,severity,info) in first.items():
        assert limited=="0",(number,"unexpected incomplete analysis")
        for rule in rules:
            actual.setdefault(rule,set()).add(number)
    assert actual==expected, json.dumps({rule:{"expected":sorted(expected.get(rule,set())),"actual":sorted(actual.get(rule,set()))}
        for rule in actual.keys()|expected.keys() if actual.get(rule)!=expected.get(rule)},indent=2)
    disabled=read(args.installed,["-o","arwah.enabled:FALSE"])
    assert all(not row[0] and not row[2] for row in disabled.values())
    quiet=read(args.installed,["-o","arwah.annotate:FALSE"])
    assert all("[Arwah:" not in row[3] for row in quiet.values())
    cached=read(args.installed,["-2","-o","arwah.cache_frames:16"])
    assert cached[max(cached)][1]=="0"
    assert all(row[1] in {"0", "1"} for row in cached.values())
    bounded=read(args.installed,["-o","arwah.max_keys:16"])
    assert any(row[1]=="1" for row in bounded.values())
    assert all(not first[n][0] for key in ["normal","syn_retries","arp_vlan","expired_a","expired_b"] for n in groups[key])
    print(f"PASS: {len(expected)} rules; {len(first)} packets; exact positive/negative matches; two-pass, preferences, cache and key limits")
    if args.live:
        live(args.installed)


if __name__=="__main__":
    main()
