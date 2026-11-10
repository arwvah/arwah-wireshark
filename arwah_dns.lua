-- Arwah DNS Lens: explainable, packet-local DNS triage for Wireshark.
-- Indicators are investigation leads, not a verdict of malicious activity.
local proto = Proto("arwah_dns", "Arwah DNS Lens")
set_plugin_info({version="1.0.0", author="arwah", description="DNS triage indicators"})

local f = {
    flagged = ProtoField.bool("arwah_dns.flagged", "Has indicators"),
    reason = ProtoField.string("arwah_dns.reason", "Indicator"),
    name = ProtoField.string("arwah_dns.name", "Query name"),
    length = ProtoField.uint32("arwah_dns.length", "Name length", base.DEC),
    entropy = ProtoField.double("arwah_dns.entropy", "Maximum label entropy (bits/character)"),
    long_name = ProtoField.bool("arwah_dns.long_name", "Long query name"),
    encoded = ProtoField.bool("arwah_dns.encoded", "Long high-entropy label"),
    txt = ProtoField.bool("arwah_dns.txt", "TXT query"),
    nxdomain = ProtoField.bool("arwah_dns.nxdomain", "NXDOMAIN reply"),
}
proto.fields = f
local hint = ProtoExpert.new("arwah_dns.indicator", "DNS triage indicator", expert.group.SECURITY, expert.severity.NOTE)
proto.experts = {hint}
proto.prefs.enabled = Pref.bool("Enabled", true, "Add DNS analysis fields")
proto.prefs.name_length = Pref.uint("Long name threshold", 70, "Minimum displayed name length, excluding a trailing dot")
proto.prefs.label_length = Pref.uint("Encoded label minimum length", 32, "Minimum label length for entropy analysis")
proto.prefs.entropy_tenths = Pref.uint("Entropy threshold (tenths)", 40, "40 means 4.0 bits per character")
proto.prefs.flag_txt = Pref.bool("Flag TXT queries", true, "TXT is also used legitimately, including SPF and DKIM")
proto.prefs.flag_nxdomain = Pref.bool("Flag NXDOMAIN replies", true, "NXDOMAIN also occurs for ordinary misspellings")

local query_names = Field.new("dns.qry.name")
local query_types = Field.new("dns.qry.type")
local response = Field.new("dns.flags.response")
local rcode = Field.new("dns.flags.rcode")

local function entropy(s)
    if #s == 0 then return 0 end
    local counts, value = {}, 0
    for i = 1, #s do
        local ch = s:sub(i, i)
        counts[ch] = (counts[ch] or 0) + 1
    end
    for _, count in pairs(counts) do
        local p = count / #s
        value = value - p * math.log(p, 2)
    end
    return value
end

function proto.dissector(_, _, tree)
    if not proto.prefs.enabled then return end
    local responses = {response()}
    -- Field offsets can overlap across reassembled DNS buffers. Skip ambiguous
    -- frames containing several messages instead of attributing fields wrongly.
    if #responses ~= 1 then return end
    local names, types, codes = {query_names()}, {query_types()}, {rcode()}
    for index, resp in ipairs(responses) do
        local start = resp.offset
        local stop = responses[index + 1] and responses[index + 1].offset or math.huge
        local is_response = resp.value == true
        local root = tree:add(proto)
        local reasons, long_name, encoded, txt, nx = {}, false, false, false, false
        for _, name_field in ipairs(names) do
            if name_field.offset >= start and name_field.offset < stop then
                local name = tostring(name_field):gsub("%.$", "")
                local maximum, suspect = 0, false
                for label in name:lower():gmatch("[^.]+") do
                    local value = entropy(label)
                    maximum = math.max(maximum, value)
                    if #label >= math.max(1, proto.prefs.label_length)
                        and value >= proto.prefs.entropy_tenths / 10 then
                        suspect = true
                    end
                end
                local item = root:add(f.name, name):set_generated()
                item:add(f.length, #name):set_generated()
                item:add(f.entropy, maximum):set_generated()
                if not is_response then
                    long_name = long_name or #name >= math.max(1, proto.prefs.name_length)
                    encoded = encoded or suspect
                end
            end
        end
        if not is_response and proto.prefs.flag_txt then
            for _, typ in ipairs(types) do
                if typ.offset >= start and typ.offset < stop and typ.value == 16 then txt = true end
            end
        end
        if is_response and proto.prefs.flag_nxdomain then
            for _, code in ipairs(codes) do
                if code.offset >= start and code.offset < stop and code.value == 3 then nx = true end
            end
        end
        if long_name then reasons[#reasons + 1] = "Long DNS query name" end
        if encoded then reasons[#reasons + 1] = "Long high-entropy label; may contain encoded data" end
        if txt then reasons[#reasons + 1] = "TXT query; inspect its purpose and response" end
        if nx then reasons[#reasons + 1] = "NXDOMAIN reply; requested name does not exist" end
        root:add(f.flagged, #reasons > 0):set_generated()
        root:add(f.long_name, long_name):set_generated()
        root:add(f.encoded, encoded):set_generated()
        root:add(f.txt, txt):set_generated()
        root:add(f.nxdomain, nx):set_generated()
        for _, reason in ipairs(reasons) do
            root:add(f.reason, reason):set_generated()
            root:add_proto_expert_info(hint, reason)
        end
    end
end

register_postdissector(proto)
