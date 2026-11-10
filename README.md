# Arwah Traffic Guard

[![Tests](https://github.com/arwvah/arwah-wireshark/actions/workflows/test.yml/badge.svg)](https://github.com/arwvah/arwah-wireshark/actions/workflows/test.yml)

A Wireshark Lua plugin that flags suspicious traffic as packets arrive. **25 explainable rules** cover TCP, UDP, ICMP/ICMPv6, DNS, HTTP, FTP, SMTP, Telnet, TLS, and ARP. Supports live captures and saved PCAP/PCAPNG files. No cloud service, API key, or compilation.

Arwah evaluates each dissected frame against applicable rules. It cannot recognize every attack or establish that unflagged traffic is safe.

## Install

Install Wireshark with Lua support and TShark, then:

```bash
git clone https://github.com/arwvah/arwah-wireshark.git
cd arwah-wireshark
python3 install.py
```

Restart Wireshark or choose **Analyze → Reload Lua Plugins**. The installer discovers your personal Lua directory and installs `arwah_traffic.lua` plus the original `arwah_dns.lua`. Replaced files are backed up under `~/.arwah-wireshark-backups/`. Plugin installation does not need root; existing capture permissions still apply.

For manual installation, copy both Lua files to **Help → About Wireshark → Folders → Personal Lua Plugins**. Do not additionally load installed copies with `-X lua_script`, which registers duplicate protocols.

## Live use

1. Start capturing on the interface to inspect.
2. Leave the **capture filter empty** to inspect all traffic visible on that interface.
3. Apply the **display filter** `arwah.flagged == 1`.
4. Look for `[Arwah: NOTE]`, `[Arwah: WARN]`, or `[Arwah: HIGH]` in the Info column.
5. Expand **Arwah Traffic Guard** in packet details for rule IDs, reasons, and counts. **Analyze → Expert Information** also lists indicators.

Threshold-crossing packets and subsequent matching packets are flagged; earlier packets are not retroactively labeled. Packet drops and capture filters can hide evidence. Only traffic reaching the selected interface can be inspected.

```text
arwah.flagged == 1
arwah.severity >= 2
arwah.severity == 3
arwah.rule == "tcp.port_scan"
arwah.rule contains "http."
arwah.limited == 1
```

Use `== 1` for booleans: field presence also matches false values. Right-click severity, rule, or reason fields and select **Apply as Column**. Optional colors can be added through **View → Coloring Rules** using severity filters; existing settings are not modified automatically.

## Rules

Rate and scan defaults use a **10-second rolling window**. Configure them in **Edit → Preferences → Protocols → Arwah Traffic Guard**. Reopen the capture after changing preferences to rebuild history.

| Rule ID | Default trigger | Severity |
| --- | --- | --- |
| `tcp.null` | No TCP flags | Warning |
| `tcp.xmas` | FIN + PSH + URG | Warning |
| `tcp.conflicting_flags` | SYN + FIN or RST | High |
| `tcp.port_scan` | 20 distinct destination ports, same source/destination | Warning |
| `tcp.host_sweep` | SYNs to 20 distinct hosts from one source | Warning |
| `tcp.syn_burst` | 100 distinct connection attempts to one destination | Warning |
| `udp.burst` | 200 packets, same source/destination | Warning |
| `icmp.echo_burst` | 50 echo requests, same source/destination | Warning |
| `icmp.large_echo` | Echo-request frame larger than 1,400 bytes | Note |
| `dns.query_burst` | 100 query packets from one client | Warning |
| `dns.nxdomain_burst` | 20 failed-name reply packets to one client | Warning |
| `dns.long_name` | Query name at least 70 characters | Note |
| `dns.encoded_label` | Label at least 32 characters with entropy at least 4 bits/character | Warning |
| `dns.txt` | TXT query | Note |
| `dns.nxdomain` | NXDOMAIN reply | Note |
| `http.basic_cleartext` | Basic authorization without TLS | High |
| `http.path_traversal` | Parent-directory syntax in URI, including double URL encoding | Warning |
| `http.sql_pattern` | UNION SELECT syntax in URI | Warning |
| `http.script_pattern` | Script-tag syntax in URI | Warning |
| `http.auth_failure_burst` | 10 HTTP 401/403 reply packets, same server/client | Warning |
| `ftp.password_cleartext` | PASS command without TLS | High |
| `smtp.auth_cleartext` | AUTH command without TLS | Warning |
| `telnet.cleartext` | Decoded Telnet | Note |
| `tls.legacy_version` | ServerHello selects SSLv3/TLS 1.0/TLS 1.1 | Warning |
| `arp.mapping_change` | Sender IPv4 changes MAC within 60s, same interface/VLAN | Warning |

SYN retries with identical IPs, ports, and sequence numbers count as one attempt while retained in the window. Busy applications, diagnostics, CDNs, authentication policies, and legitimate failover can trigger these rules.

## Terminal use

```bash
tshark -D
# Replace YOUR_INTERFACE with an interface from the list.
tshark -l -i YOUR_INTERFACE -Y 'arwah.flagged == 1' \
  -T fields -e frame.time -e ip.src -e ipv6.src -e arwah.severity -e arwah.rule -e arwah.reason

tshark -r samples/traffic-demo.pcap -Y 'arwah.flagged == 1' \
  -T fields -e frame.number -e arwah.rule -e arwah.reason
```

Open `samples/traffic-demo.pcap` for a synthetic demonstration: documentation IP ranges, fabricated MACs, `.test` names, and dummy credentials. The original DNS sample and `arwah_dns.*` filters remain available.

## Limits and privacy

- Heuristics provide investigation leads, not malware verdicts, a firewall, or a full IDS. Severity is triage priority, not attack probability.
- Encrypted application contents need Wireshark decryption. HTTP/2, HTTP/3, SMB exploits, file malware scanning, reputation feeds, and general brute-force detection are not implemented.
- Rules depend on successful Wireshark dissection. Truncation, malformed traffic, reassembly, and unusual ports can hide evidence. HTTP URI checks cover the first 8,192 displayed characters, not request bodies. Most application checks use the first field occurrence in a frame; multiple DNS messages are skipped and marked limited.
- Packet counts are not session counts; coalesced application messages can be undercounted. Transport rules use the first decoded IP/transport fields; tunnels and overlapping addresses across interfaces/VLANs can conflate counters. ARP is scoped by interface/VLAN.
- Full dissection adds CPU cost; throughput is not guaranteed. Watch Wireshark's packet-drop counters.
- Memory is bounded: 4,096 window keys, 256 recent events per key, 100,000 cached frame results, and a bounded ARP map by default. Count thresholds are clamped to 2–256. Counts are lower bounds; heavy windows may lose older distinct-event evidence.
- `arwah.limited == 1` exposes key eviction, uncached historical revisits, gaps, reversed timestamps, or ambiguous DNS. Cached revisits do not increment counters. Fieldless preliminary passes defer analysis until fields exist. Uncached older frames get packet-local checks only. Reopen with a larger cache for long captures.
- The plugin sends no data, saves no credentials, starts no captures, and blocks no connections. Alert reasons omit credential values; Wireshark still displays captured contents.

## Test and uninstall

Python/Scapy are only development dependencies. Runtime requires only Wireshark's Lua support.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
# Before plugin installation:
.venv/bin/python tests/verify.py
.venv/bin/python tests/verify_traffic.py
# After plugin installation:
.venv/bin/python tests/verify.py --installed
.venv/bin/python tests/verify_traffic.py --installed
# Optional live test, capturing only self-generated localhost UDP:
.venv/bin/python tests/verify_traffic.py --installed --live
# Uninstall, preserving backups:
python3 install.py --uninstall
```

Restart Wireshark after uninstalling. Tests cover exact flagged frames, normal controls, IPv6, expiry, SYN retries, two-pass consistency, preference toggles, and bounded storage. GitHub Actions runs offline tests. See [VERIFICATION.md](VERIFICATION.md).

## License and references

Apache-2.0. Built with Wireshark's [Lua postdissector API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html) and [field extractors](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Field.html).
