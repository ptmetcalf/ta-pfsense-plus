#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  tools/splunk-pfsense-rule-lookup.sh --host <host> [--user <user>] [--port <port>] [--output <csv>]

Pulls pfSense config.xml over SSH and builds a Splunk lookup mapping
filterlog rule/tracker_id -> rule_name.

Defaults:
  --user   admin
  --port   22
  --output lookups/pfsense_filter_rule_map.csv
EOF
}

host=""
user="admin"
port="22"
output="lookups/pfsense_filter_rule_map.csv"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      host="$2"
      shift 2
      ;;
    --user)
      user="$2"
      shift 2
      ;;
    --port)
      port="$2"
      shift 2
      ;;
    --output)
      output="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$host" ]]; then
  echo "Missing --host" >&2
  usage >&2
  exit 1
fi

tmp_xml="$(mktemp)"
tmp_pfctl="$(mktemp)"
control_path="/tmp/ssh-pfsense-${user//[^a-zA-Z0-9]/_}-${host//[^a-zA-Z0-9]/_}-${port}"
ssh_cmd=(ssh -p "$port" -o ControlMaster=auto -o ControlPersist=60s -o ControlPath="$control_path")
trap 'rm -f "$tmp_xml" "$tmp_pfctl"; ${ssh_cmd[@]} -O exit "${user}@${host}" >/dev/null 2>&1 || true' EXIT

${ssh_cmd[@]} "${user}@${host}" "cat /cf/conf/config.xml" > "$tmp_xml"
if ! ${ssh_cmd[@]} "${user}@${host}" "pfctl -sr" > "$tmp_pfctl"; then
  echo "Warning: failed to run pfctl -sr; continuing with config.xml only." >&2
  : > "$tmp_pfctl"
fi

mkdir -p "$(dirname "$output")"

python3 - "$tmp_xml" "$tmp_pfctl" "$output" <<'PY'
import csv
import re
import sys
import xml.etree.ElementTree as ET

xml_path = sys.argv[1]
pfctl_path = sys.argv[2]
out_path = sys.argv[3]

tree = ET.parse(xml_path)
root = tree.getroot()

def text(node, path):
    if node is None:
        return ""
    value = node.findtext(path, default="").strip()
    return value

def build_endpoint(node):
    if node is None:
        return ""
    if text(node, "any"):
        return "any"
    address = text(node, "address")
    network = text(node, "network")
    port = text(node, "port")
    value = address or network
    if value and port:
        return f"{value}:{port}"
    return value or port

rows = []
for idx, rule in enumerate(root.findall("./filter/rule"), start=1):
    tracker = text(rule, "tracker")
    if not tracker:
        continue
    descr = text(rule, "descr")
    if not descr:
        descr = f"rule_{tracker}"
    tracker_numeric = ""
    if tracker.isdigit():
        tracker_numeric = str(int(tracker))
    action = text(rule, "type")
    interface = text(rule, "interface")
    source = build_endpoint(rule.find("source"))
    destination = build_endpoint(rule.find("destination"))
    gateway = text(rule, "gateway")
    rule_type = text(rule, "ipprotocol") or text(rule, "protocol")
    rows.append(
        (
            idx,
            tracker,
            descr,
            tracker_numeric,
            action,
            interface,
            source,
            destination,
            gateway,
            rule_type,
            "user",
        )
    )

def normalize_label(label):
    label = label.strip()
    if label.startswith("USER_RULE:"):
        return label.split(":", 1)[1].strip()
    return label

label_re = re.compile(r'label\s+"([^"]+)"')
ridentifier_re = re.compile(r"\bridentifier\s+(\d+)\b")
icmp6_type_re = re.compile(r"\bicmp6-type\s+(\S+)\b")
proto_re = re.compile(r"\bproto\s+(\S+)\b")
inet_re = re.compile(r"\b(inet6|inet)\b")
direction_re = re.compile(r"\b(in|out)\b")
on_iface_re = re.compile(r"\bon\s+(\S+)\b")
route_to_re = re.compile(r"\broute-to\s+\((\S+)\s")
action_re = re.compile(r"^(pass|block)\b")

def normalize_proto(value):
    if not value:
        return "Any"
    value = value.strip().lower()
    if value in {"ipv6-icmp", "icmp6"}:
        return "ICMP6"
    if value == "icmp":
        return "ICMP"
    if value.isalpha():
        return value.upper()
    return value

def parse_pfctl_summary(lines):
    first = lines[0] if lines else ""
    match_action = action_re.search(first)
    action = match_action.group(1) if match_action else ""
    match_inet = inet_re.search(first)
    inet = match_inet.group(1) if match_inet else ""
    match_proto = proto_re.search(first)
    proto = match_proto.group(1) if match_proto else ""
    match_direction = direction_re.search(first)
    direction = match_direction.group(1) if match_direction else ""
    match_route = route_to_re.search(first)
    iface = f"route-to {match_route.group(1)}" if match_route else ""
    if not iface:
        match_on = on_iface_re.search(first)
        if match_on:
            iface = f"on {match_on.group(1)}"

    icmp6_types = set()
    for line in lines:
        icmp6_types.update(icmp6_type_re.findall(line))
    if icmp6_types and not proto:
        proto = "icmp6"

    return {
        "action": action,
        "inet": inet,
        "proto": proto,
        "direction": direction,
        "iface": iface,
        "icmp6_types": sorted(icmp6_types),
    }

def build_standard_name(summary, label=None):
    action = summary["action"]
    action_label = "Any"
    if action == "pass":
        action_label = "Allow"
    elif action == "block":
        action_label = "Block"

    inet_label = "Any"
    if summary["inet"] == "inet":
        inet_label = "IPv4"
    elif summary["inet"] == "inet6":
        inet_label = "IPv6"

    direction = summary["direction"]
    direction_label = "Any"
    if direction == "in":
        direction_label = "In"
    elif direction == "out":
        direction_label = "Out"

    proto_label = normalize_proto(summary["proto"])
    iface = summary["iface"]
    iface_label = "Any"
    if iface.startswith("route-to "):
        iface_label = f"Route-to {iface.split(' ', 1)[1]}"
    elif iface.startswith("on "):
        iface_label = f"On {iface.split(' ', 1)[1]}"

    name = f"System | {action_label} | {direction_label} | {inet_label} | {proto_label} | {iface_label}"
    if summary["icmp6_types"]:
        types = ",".join(summary["icmp6_types"])
        name = f"{name} ({types})"
    if label:
        name = f"{name} ({label})"
    return name

pfctl_by_tracker = {}

try:
    with open(pfctl_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or "ridentifier" not in line:
                continue
            match_id = ridentifier_re.search(line)
            if not match_id:
                continue
            tracker = match_id.group(1)
            entry = pfctl_by_tracker.setdefault(tracker, {"labels": [], "lines": []})
            entry["lines"].append(line)
            labels = label_re.findall(line)
            for candidate in labels:
                if candidate.lower().startswith("id:"):
                    continue
                entry["labels"].append(normalize_label(candidate))
except FileNotFoundError:
    pass

existing_trackers = {row[1] for row in rows}
next_rule = len(rows) + 1
for tracker, data in pfctl_by_tracker.items():
    if tracker in existing_trackers:
        continue
    labels = data["labels"]
    summary = parse_pfctl_summary(data["lines"])
    label = labels[0] if labels else ""
    label = build_standard_name(summary, label=label)
    action = summary["action"]
    tracker_numeric = str(int(tracker)) if tracker.isdigit() else ""
    rows.append(
        (
            next_rule,
            tracker,
            label,
            tracker_numeric,
            action,
            "",
            "",
            "",
            "",
            "",
            "system",
        )
    )
    existing_trackers.add(tracker)
    next_rule += 1

rows.sort(key=lambda r: r[0])

with open(out_path, "w", newline="") as handle:
    writer = csv.writer(handle)
    writer.writerow(
        [
            "rule",
            "tracker_id",
            "rule_name",
            "tracker_id_numeric",
            "action",
            "interface",
            "source",
            "destination",
            "gateway",
            "type",
            "rule_origin",
        ]
    )
    for row in rows:
        writer.writerow(row)
PY

echo "Wrote lookup: $output"
