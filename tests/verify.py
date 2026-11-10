#!/usr/bin/env python3
"""Generate offline packets and verify plugin behavior with real TShark."""
import argparse
import pathlib
import struct
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
PCAP = ROOT / "samples" / "dns-demo.pcap"


def dns(name, kind=1, flags=0x0100):
    encoded = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!6H", 1234, flags, 1, 0, 0, 0) + encoded + struct.pack("!HH", kind, 1)


def frame(payload, reply=False, port=53):
    src, dst = (53, 42000) if reply else (42000, port)
    udp = struct.pack("!4H", src, dst, len(payload) + 8, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 2 if reply else 1]), bytes([192, 0, 2, 1 if reply else 2]))
    checksum = sum(struct.unpack("!10H", ip))
    while checksum >> 16:
        checksum = (checksum & 65535) + (checksum >> 16)
    ip = ip[:10] + struct.pack("!H", (~checksum) & 65535) + ip[12:]
    return bytes.fromhex("0200000000020200000000010800") + ip + udp


def make_capture():
    long = "a" * 40 + "." + "b" * 30 + ".example.test"
    encoded = "abcdefghijklmnopqrstuvwxyz0123456789.example.test"
    packets = [
        frame(dns("www.example.test")),
        frame(dns(long)),
        frame(dns(encoded)),
        frame(dns("example.test", 16)),
        frame(dns("missing.example.test", flags=0x8183), True),
        frame(dns(encoded, flags=0x8180), True),
        frame(b"non-DNS traffic", port=9999),
        frame(dns("a" * 31 + ".example.test")),
        frame(dns("example.test", 16, flags=0x8180), True),
        frame(dns("a" * 56 + ".example.test")),  # 69 chars: below threshold
        frame(dns("a" * 57 + ".example.test")),  # 70 chars: at threshold
    ]
    PCAP.parent.mkdir(exist_ok=True)
    with PCAP.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for n, packet in enumerate(packets):
            out.write(struct.pack("<IIII", 1700000000 + n, 0, len(packet), len(packet)))
            out.write(packet)


def run(args, installed):
    command = ["tshark", "-n"]
    if not installed:
        command += ["-X", f"lua_script:{ROOT / 'arwah_dns.lua'}"]
    result = subprocess.run(command + ["-r", str(PCAP)] + args,
                            capture_output=True, text=True, check=True)
    assert "Lua" not in result.stderr, result.stderr
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args()
    make_capture()
    checks = {
        "arwah_dns.flagged == 1": "2\n3\n4\n5\n11",
        "arwah_dns.long_name == 1": "2\n11",
        "arwah_dns.encoded == 1": "3",
        "arwah_dns.txt == 1": "4",
        "arwah_dns.nxdomain == 1": "5",
        "_ws.lua.error": "",
        "_ws.malformed": "",
    }
    count = 0
    for mode in ([], ["-2"]):
        for display_filter, expected in checks.items():
            actual = run(mode + ["-Y", display_filter, "-T", "fields", "-e", "frame.number"], args.installed)
            assert actual == expected, (mode, display_filter, expected, actual)
            count += 1
    for preference, expected in [("enabled:FALSE", ""), ("name_length:200", "3\n4\n5"),
                                  ("flag_txt:FALSE", "2\n3\n5\n11"),
                                  ("flag_nxdomain:FALSE", "2\n3\n4\n11")]:
        actual = run(["-o", "arwah_dns." + preference, "-Y", "arwah_dns.flagged == 1",
                      "-T", "fields", "-e", "frame.number"], args.installed)
        assert actual == expected, (preference, expected, actual)
        count += 1
    print(f"PASS: {count} TShark checks; {PCAP}")


if __name__ == "__main__":
    main()
