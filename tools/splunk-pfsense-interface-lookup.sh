#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  tools/splunk-pfsense-interface-lookup.sh --host <host> [--user <user>] [--port <port>] [--output <csv>]

Pulls pfSense config.xml over SSH and builds a Splunk lookup mapping
interface -> description (plus interface_id/source).

Defaults:
  --user   admin
  --port   22
  --output lookups/pfsense_interface_map.csv
EOF
}

host=""
user="admin"
port="22"
output="lookups/pfsense_interface_map.csv"

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
control_path="/tmp/ssh-pfsense-${user//[^a-zA-Z0-9]/_}-${host//[^a-zA-Z0-9]/_}-${port}"
ssh_cmd=(ssh -p "$port" -o ControlMaster=auto -o ControlPersist=60s -o ControlPath="$control_path")
trap 'rm -f "$tmp_xml"; ${ssh_cmd[@]} -O exit "${user}@${host}" >/dev/null 2>&1 || true' EXIT

${ssh_cmd[@]} "${user}@${host}" "cat /cf/conf/config.xml" > "$tmp_xml"

mkdir -p "$(dirname "$output")"

python3 - "$tmp_xml" "$output" <<'PY'
import csv
import sys
import xml.etree.ElementTree as ET

xml_path = sys.argv[1]
out_path = sys.argv[2]

tree = ET.parse(xml_path)
root = tree.getroot()

entries = {}

def add_entry(interface, description, interface_id, source):
    interface = (interface or "").strip()
    description = (description or "").strip()
    interface_id = (interface_id or "").strip()
    if not interface:
        return
    if not description:
        description = interface_id or interface
    entries[interface] = (description, interface_id, source)

interfaces = root.find("interfaces")
if interfaces is not None:
    for iface in list(interfaces):
        interface_id = iface.tag or ""
        ifname = iface.findtext("if", default="").strip()
        descr = iface.findtext("descr", default="").strip()
        add_entry(ifname, descr, interface_id, "interfaces")

vlans = root.find("vlans")
if vlans is not None:
    for vlan in vlans.findall("vlan"):
        vlanif = vlan.findtext("vlanif", default="").strip()
        descr = vlan.findtext("descr", default="").strip()
        add_entry(vlanif, descr, "vlan", "vlans")

bridges = root.find("bridges")
if bridges is not None:
    for bridge in bridges.findall("bridge"):
        member = bridge.findtext("members", default="").strip()
        descr = bridge.findtext("descr", default="").strip()
        add_entry(member, descr, "bridge", "bridges")

rows = sorted((iface, *data) for iface, data in entries.items())

with open(out_path, "w", newline="") as handle:
    writer = csv.writer(handle)
    writer.writerow(["interface", "description", "interface_id", "source"])
    writer.writerows(rows)
PY

echo "Wrote lookup: $output"
