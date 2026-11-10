# Verification

Local validation on 2026-11-10 with TShark/Wireshark 4.7.3, Lua 5.4.9, Python 3.13, and Scapy 2.8.0:

- All 18 original DNS regression checks passed after installation.
- The 751-packet synthetic capture matched the exact expected frame sets for all 25 traffic rules: 51 flagged frames overall.
- Normal HTTP/UDP/DNS/ICMP controls, repeated identical SYN attempts, separate ARP VLANs, and expired scan windows did not trigger traffic rules.
- IPv6 TCP scanning and ICMPv6 bursts were detected.
- Single-pass and two-pass output matched for rule IDs, severity, and history status.
- Enable/disable preferences, annotation disabling, small result-cache settings, and key eviction were exercised.
- No Lua errors or malformed packets occurred in the final synthetic traffic fixture.
- An actual live TShark capture on `lo`, filtered to a temporary localhost UDP port, observed a generated 20-packet burst. With a test threshold of 10, it emitted 11 `udp.burst` flags. This was repeated successfully with the installed plugin.

The live test did not use external hosts or capture unrelated interface traffic. The repository contains only synthetic captures, not the loopback test capture or personal network data.

GUI interaction, sustained high-throughput capture, and exhaustive protocol/reassembly behavior were not visually/load tested. A lower cache size bounds memory; very old frame revisits may lose stateful results and expose `arwah.limited`. This test suite is functional evidence, not a detection-rate or false-positive benchmark.

GitHub Actions runs the offline suites against its Ubuntu-packaged TShark. The repository's Actions badge reports the current CI result.
