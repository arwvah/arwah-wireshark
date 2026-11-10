-- Arwah Traffic Guard. Packet and rolling-window indicators, not attack verdicts.
local proto = Proto("arwah", "Arwah Traffic Guard")
set_plugin_info({version="2.0.0", author="arwah", description="Live multi-protocol traffic triage"})
local fields = {
    checked = ProtoField.bool("arwah.checked", "Analyzed by Arwah"),
    flagged = ProtoField.bool("arwah.flagged", "Has indicators"),
    severity = ProtoField.uint8("arwah.severity", "Highest severity", base.DEC,
        {[0]="None", [1]="Note", [2]="Warning", [3]="High"}),
    rule = ProtoField.string("arwah.rule", "Rule"),
    reason = ProtoField.string("arwah.reason", "Explanation"),
    count = ProtoField.uint32("arwah.count", "Observed count (bounded)"),
    limited = ProtoField.bool("arwah.limited", "Analysis history limited"),
}
proto.fields = fields
local experts = {
    ProtoExpert.new("arwah.note", "Traffic indicator", expert.group.SECURITY, expert.severity.NOTE),
    ProtoExpert.new("arwah.warning", "Suspicious traffic pattern", expert.group.SECURITY, expert.severity.WARN),
    ProtoExpert.new("arwah.high", "High priority traffic indicator", expert.group.SECURITY, expert.severity.ERROR),
}
proto.experts = experts
proto.prefs.enabled = Pref.bool("Enabled", true, "Analyze packets as Wireshark dissects them")
proto.prefs.annotate = Pref.bool("Annotate Info column", true, "Append the highest alert severity")
proto.prefs.window = Pref.uint("Rolling window seconds", 10, "Capture timestamps determine the window")
proto.prefs.scan_ports = Pref.uint("Distinct TCP ports", 20, "Per source and destination, initial SYN packets")
proto.prefs.sweep_hosts = Pref.uint("Distinct TCP destination hosts", 20, "Per source, initial SYN packets")
proto.prefs.syn_rate = Pref.uint("Distinct SYN attempts", 100, "Per destination; retries of the same attempt are deduplicated")
proto.prefs.udp_rate = Pref.uint("UDP packet count", 200, "Per source and destination; busy legitimate traffic also triggers")
proto.prefs.icmp_rate = Pref.uint("ICMP echo request count", 50, "Per source and destination")
proto.prefs.dns_rate = Pref.uint("DNS query count", 100, "Per client")
proto.prefs.nxdomain_rate = Pref.uint("NXDOMAIN response count", 20, "Per client")
proto.prefs.auth_failures = Pref.uint("HTTP 401/403 response count", 10, "Per server and client; not proof of brute force")
proto.prefs.dns = Pref.bool("DNS indicators", true, "Long names, entropy, TXT and NXDOMAIN")
proto.prefs.application = Pref.bool("Application indicators", true, "HTTP, FTP, SMTP, Telnet and old TLS")
proto.prefs.arp = Pref.bool("ARP mapping changes", true, "Flag IPv4-to-MAC changes observed within 60 seconds")
proto.prefs.max_keys = Pref.uint("Maximum tracked window keys", 4096, "Old keys are evicted; 16 to 65536")
proto.prefs.cache_frames = Pref.uint("Cached frame results", 100000, "Older revisits report limited history; 16 to 1000000")

local extract = {}
for _, name in ipairs({
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.flags", "tcp.srcport", "tcp.dstport", "tcp.seq_raw",
    "udp.srcport", "icmp.type", "icmpv6.type", "http.authorization", "http.request.uri", "http.response.code",
    "ftp.request.command", "smtp.req.command", "telnet", "tls", "tls.handshake.type", "tls.handshake.version",
    "arp.src.proto_ipv4", "arp.src.hw_mac", "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.flags.rcode",
    "frame.interface_id", "vlan.id", "frame.number",
}) do extract[name] = Field.new(name) end
local function value(name)
    local field = extract[name]()
    if field then return field.value end
    return nil
end
local function string_value(name)
    local field = extract[name]()
    return field and tostring(field) or nil
end
local function clamp(n, low, high) return math.max(low, math.min(high, n)) end
local windows, key_ring, next_key, cache, highest, last_time, arp, arp_ring, arp_next, limited_until
local function reset()
    windows, key_ring, next_key, cache = {}, {}, 1, {}
    highest, last_time, arp, arp_ring, arp_next, limited_until = 0, nil, {}, {}, 1, -1
end
proto.init = reset
proto.prefs_changed = reset
reset()

-- A ring of at most 256 events per key bounds memory and per-packet work.
-- All count thresholds are clamped to 256; reported counts are lower bounds.
local function observe(key, timestamp, distinct_value)
    local width = math.max(1, proto.prefs.window)
    local bucket = windows[key]
    if not bucket then
        local maximum = clamp(proto.prefs.max_keys, 16, 65536)
        local old = key_ring[next_key]
        if old then
            if windows[old] and windows[old].last >= timestamp - width then
                limited_until = timestamp + width
            end
            windows[old] = nil
        end
        key_ring[next_key] = key
        next_key = next_key % maximum + 1
        bucket = {events={}, head=1, size=0, values={}, unique=0, last=timestamp}
        windows[key] = bucket
    end
    local function pop()
        local event = bucket.events[bucket.head]
        if event[2] then
            bucket.values[event[2]] = bucket.values[event[2]] - 1
            if bucket.values[event[2]] == 0 then
                bucket.values[event[2]] = nil
                bucket.unique = bucket.unique - 1
            end
        end
        bucket.events[bucket.head] = nil
        bucket.head = bucket.head % 256 + 1
        bucket.size = bucket.size - 1
    end
    while bucket.size > 0 and bucket.events[bucket.head][1] < timestamp - width do pop() end
    if bucket.size == 256 then pop() end
    local slot = (bucket.head + bucket.size - 1) % 256 + 1
    bucket.events[slot] = {timestamp, distinct_value}
    bucket.size, bucket.last = bucket.size + 1, timestamp
    if distinct_value then
        if not bucket.values[distinct_value] then bucket.unique = bucket.unique + 1 end
        bucket.values[distinct_value] = (bucket.values[distinct_value] or 0) + 1
        return bucket.unique
    end
    return bucket.size
end

local function entropy(text)
    local counts, result = {}, 0
    for i=1,#text do
        local ch = text:sub(i,i)
        counts[ch] = (counts[ch] or 0) + 1
    end
    for _, count in pairs(counts) do
        local p = count / #text
        result = result - p * math.log(p, 2)
    end
    return result
end

local function analyze(pinfo, timestamp, track)
    local result = {alerts={}, severity=0, limited=false}
    local seen = {}
    local function alert(rule, severity, reason, count)
        if seen[rule] then return end
        seen[rule] = true
        result.alerts[#result.alerts + 1] = {rule, severity, reason, count}
        result.severity = math.max(result.severity, severity)
    end
    local src = string_value("ip.src") or string_value("ipv6.src")
    local dst = string_value("ip.dst") or string_value("ipv6.dst")
    local pair = src and dst and (src .. ">" .. dst)
    local function rate(rule, key, threshold, reason, unique)
        if not track or not key then return end
        local count = observe(rule .. ":" .. key, timestamp, unique)
        if count >= clamp(threshold, 2, 256) then
            alert(rule, 2, reason .. string.format(" (%d within %ds)", count, math.max(1, proto.prefs.window)), count)
        end
    end

    local flags = value("tcp.flags")
    if flags then
        local function has(bit) return math.floor(flags / bit) % 2 == 1 end
        local syn, ack, fin, rst = has(2), has(16), has(1), has(4)
        if flags % 512 == 0 then alert("tcp.null", 2, "TCP packet has no flags; possible NULL probe") end
        if fin and has(8) and has(32) then alert("tcp.xmas", 2, "TCP FIN/PSH/URG flags; possible Xmas probe") end
        if syn and (fin or rst) then alert("tcp.conflicting_flags", 3, "TCP SYN combined with FIN or RST") end
        if syn and not ack and not fin and not rst and pair then
            local port = tostring(value("tcp.dstport"))
            rate("tcp.port_scan", pair, proto.prefs.scan_ports, "Many destination TCP ports", port)
            rate("tcp.host_sweep", src, proto.prefs.sweep_hosts, "Many destination hosts reached with TCP SYN", dst)
            local attempt = pair .. ":" .. tostring(value("tcp.srcport")) .. ":" .. port .. ":" .. tostring(value("tcp.seq_raw"))
            rate("tcp.syn_burst", dst, proto.prefs.syn_rate, "Many distinct TCP connection attempts to one destination", attempt)
        end
    end
    if value("udp.srcport") then
        rate("udp.burst", pair, proto.prefs.udp_rate, "High UDP packet count; check application context")
    end
    if value("icmp.type") == 8 or value("icmpv6.type") == 128 then
        rate("icmp.echo_burst", pair, proto.prefs.icmp_rate, "Many ICMP echo requests")
        if pinfo.len > 1400 then alert("icmp.large_echo", 1, "Large ICMP echo request; diagnostics can also cause this") end
    end

    if proto.prefs.dns then
        local responses = {extract["dns.flags.response"]()}
        if #responses == 1 then
            if responses[1].value == false then
                rate("dns.query_burst", src, proto.prefs.dns_rate, "High DNS query count from one client")
                for _, name in ipairs({extract["dns.qry.name"]()}) do
                    local text = tostring(name):lower():gsub("%.$", "")
                    if #text >= 70 then alert("dns.long_name", 1, "DNS query name has at least 70 characters") end
                    for label in text:gmatch("[^.]+") do
                        if #label >= 32 and entropy(label) >= 4 then
                            alert("dns.encoded_label", 2, "Long high-entropy DNS label; may contain encoded data")
                        end
                    end
                end
                for _, kind in ipairs({extract["dns.qry.type"]()}) do
                    if kind.value == 16 then alert("dns.txt", 1, "DNS TXT query; often legitimate") end
                end
            elseif value("dns.flags.rcode") == 3 then
                alert("dns.nxdomain", 1, "DNS name does not exist")
                rate("dns.nxdomain_burst", dst, proto.prefs.nxdomain_rate, "Many NXDOMAIN replies to one client")
            end
        elseif #responses > 1 then
            result.limited = true
        end
    end

    if proto.prefs.application then
        local encrypted = extract.tls() ~= nil
        local authorization = string_value("http.authorization")
        if authorization and authorization:lower():match("^basic%s") and not encrypted then
            alert("http.basic_cleartext", 3, "HTTP Basic credentials visible without TLS; credential value omitted")
        end
        if not encrypted and string_value("ftp.request.command") == "PASS" then
            alert("ftp.password_cleartext", 3, "FTP password command visible without TLS; password omitted")
        end
        if not encrypted and string_value("smtp.req.command") == "AUTH" then
            alert("smtp.auth_cleartext", 2, "SMTP authentication attempted without TLS; mechanism may affect exposure")
        end
        if extract.telnet() and not encrypted then alert("telnet.cleartext", 1, "Telnet traffic is unencrypted") end
        local uri = string_value("http.request.uri")
        if uri then
            uri = uri:sub(1,8192):lower()
            for _=1,2 do uri = uri:gsub("%%(%x%x)", function(hex) return string.char(tonumber(hex,16)) end) end
            uri = uri:gsub("+", " ")
            if uri:find("../",1,true) or uri:find("..\\",1,true) then
                alert("http.path_traversal", 2, "HTTP URI contains parent-directory traversal syntax")
            end
            if uri:match("union%s+select") or uri:match("union%s+all%s+select") then
                alert("http.sql_pattern", 2, "HTTP URI contains UNION SELECT syntax; inspect request context")
            end
            if uri:find("<script",1,true) then alert("http.script_pattern", 2, "HTTP URI contains a script-tag pattern") end
        end
        local code = value("http.response.code")
        if code == 401 or code == 403 then
            rate("http.auth_failure_burst", pair, proto.prefs.auth_failures, "Repeated HTTP 401/403 replies")
        end
        if value("tls.handshake.type") == 2 then
            local version = value("tls.handshake.version")
            if version and version <= 0x0302 then
                alert("tls.legacy_version", 2, "ServerHello selects SSLv3/TLS 1.0/TLS 1.1")
            end
        end
    end

    if track and proto.prefs.arp then
        local ip, mac = string_value("arp.src.proto_ipv4"), string_value("arp.src.hw_mac")
        if ip and mac and ip ~= "0.0.0.0" then
            -- VLAN/interface scope prevents cross-network mapping comparisons.
            local scope = tostring(value("frame.interface_id")) .. ":" .. tostring(value("vlan.id")) .. ":" .. ip
            local previous = arp[scope]
            if previous and previous.mac ~= mac and timestamp - previous.time <= 60 then
                alert("arp.mapping_change", 2, "ARP sender IP changed MAC within 60s; possible spoofing or failover")
            end
            if not previous then
                local old = arp_ring[arp_next]
                if old then
                    if arp[old].time >= timestamp - 60 then limited_until = math.max(limited_until, timestamp + 60) end
                    arp[old] = nil
                end
                arp_ring[arp_next] = scope
                arp_next = arp_next % clamp(proto.prefs.max_keys, 16, 65536) + 1
            end
            arp[scope] = {mac=mac, time=timestamp}
        end
    end
    if track and timestamp <= limited_until then result.limited = true end
    return result
end

function proto.dissector(_, pinfo, tree)
    if not proto.prefs.enabled then return end
    -- Some Wireshark builds run a fieldless preliminary pass even with
    -- allfields=true. Do not cache empty results or advance counters there.
    if value("frame.number") == nil then return end
    local number, timestamp = pinfo.number, pinfo.abs_ts
    local capacity = clamp(proto.prefs.cache_frames, 16, 1000000)
    local slot = (number - 1) % capacity + 1
    local cached = cache[slot]
    local result
    if cached and cached.number == number then
        result = cached.result
    elseif number > highest then
        -- Process only the first field-bearing visit, monotonically. A gap
        -- means earlier frames were not analyzed and is surfaced to the user.
        if number > highest + 1 then limited_until = timestamp + math.max(60, proto.prefs.window) end
        local reversed = last_time and timestamp < last_time
        if reversed then
            windows, key_ring, next_key, arp, arp_ring, arp_next = {}, {}, 1, {}, {}, 1
            limited_until = timestamp + math.max(60, proto.prefs.window)
        end
        result = analyze(pinfo, timestamp, true)
        highest, last_time = number, timestamp
        cache[slot] = {number=number, result=result}
    else
        result = analyze(pinfo, timestamp, false)
        result.limited = true
    end
    local root = tree:add(proto)
    root:add(fields.checked, true):set_generated()
    root:add(fields.flagged, #result.alerts > 0):set_generated()
    root:add(fields.severity, result.severity):set_generated()
    root:add(fields.limited, result.limited):set_generated()
    for _, entry in ipairs(result.alerts) do
        local item = root:add(fields.rule, entry[1]):set_generated()
        item:add(fields.reason, entry[3]):set_generated()
        if entry[4] then item:add(fields.count, entry[4]):set_generated() end
        item:add_proto_expert_info(experts[entry[2]], entry[3])
    end
    if result.limited then
        root:add_proto_expert_info(experts[1], "Analysis history limited: cache/key eviction, timestamp reversal, or multiple DNS messages")
    end
    if result.severity > 0 and proto.prefs.annotate then
        local label = ({"NOTE", "WARN", "HIGH"})[result.severity]
        if not tostring(pinfo.cols.info):find("[Arwah:", 1, true) then pinfo.cols.info:append(" [Arwah: " .. label .. "]") end
    end
end

-- Stateful rules need decoded fields on TShark's first pass as well.
register_postdissector(proto, true)
