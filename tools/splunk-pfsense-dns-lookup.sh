#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  tools/splunk-pfsense-dns-lookup.sh --host <host> [--user <user>] [--port <port>] [--output <csv>]

Pulls pfSense config.xml over SSH and builds a Splunk lookup mapping
ip -> hostname from Unbound host overrides and DHCP static mappings.

Defaults:
  --user             admin
  --port             22
  --output           lookups/pfsense_dns_hosts.csv
EOF
}

host=""
user="admin"
port="22"
output="lookups/pfsense_dns_hosts.csv"

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

def add_entry(ip, hostname, source):
    ip = (ip or "").strip()
    hostname = (hostname or "").strip()
    if not ip or not hostname:
        return
    entries[(ip, hostname)] = source

def build_hostname(host, domain):
    host = (host or "").strip()
    domain = (domain or "").strip()
    if not host:
        return ""
    if domain:
        return f"{host}.{domain}".strip(".")
    return host

# Unbound host overrides (pfSense stores each entry under <unbound><hosts>...</hosts>)
for host in root.findall("./unbound/hosts"):
    ip = host.findtext("ip", default="")
    hostname = build_hostname(host.findtext("host", default=""), host.findtext("domain", default=""))
    add_entry(ip, hostname, "unbound_host_override")
    for alias in host.findall("./aliases/*"):
        alias_name = build_hostname(alias.findtext("host", default=""), alias.findtext("domain", default=""))
        add_entry(ip, alias_name, "unbound_host_alias")

# DNS Forwarder (dnsmasq) host overrides
for host in root.findall("./dnsmasq/hosts/host"):
    ip = host.findtext("ip", default="")
    hostname = build_hostname(host.findtext("host", default=""), host.findtext("domain", default=""))
    add_entry(ip, hostname, "dnsmasq_host_override")
    for alias in host.findall("./aliases/*"):
        alias_name = build_hostname(alias.findtext("host", default=""), alias.findtext("domain", default=""))
        add_entry(ip, alias_name, "dnsmasq_host_alias")

# DHCP static mappings across interfaces
for section in root.findall("./dhcpd/*"):
    for mapping in section.findall("./staticmap"):
        ip = mapping.findtext("ipaddr", default="")
        hostname = mapping.findtext("hostname", default="")
        add_entry(ip, hostname, "dhcp_static")

rows = sorted(((ip, hostname, source) for (ip, hostname), source in entries.items()))

with open(out_path, "w", newline="") as handle:
    writer = csv.writer(handle)
    writer.writerow(["ip", "hostname", "source"])
    writer.writerows(rows)
PY

echo "Wrote lookup: $output"
