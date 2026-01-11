#!/usr/bin/env python3
import argparse
import ipaddress
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET

DNS_FIELDS = ["ip", "hostname"]
INTERFACE_FIELDS = ["interface", "interface_name", "interface_description"]
RULE_FIELDS = [
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
ZONE_FIELDS = ["cidr", "zone"]


def sanitize_control_component(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]", "_", value)


class SshSession:
    def __init__(self, host: str, user: str, port: int) -> None:
        self.host = host
        self.user = user
        self.port = port
        control_path = (
            f"/tmp/ssh-pfsense-{sanitize_control_component(user)}-"
            f"{sanitize_control_component(host)}-{port}"
        )
        self.base_cmd = [
            "ssh",
            "-p",
            str(port),
            "-o",
            "ControlMaster=auto",
            "-o",
            "ControlPersist=60s",
            "-o",
            f"ControlPath={control_path}",
        ]

    def run(self, command: str) -> str:
        result = subprocess.run(
            [*self.base_cmd, f"{self.user}@{self.host}", command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout

    def close(self) -> None:
        subprocess.run(
            [*self.base_cmd, "-O", "exit", f"{self.user}@{self.host}"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def load_config_xml(config_xml: Optional[str], host: Optional[str], user: str, port: int) -> ET.Element:
    if config_xml:
        return ET.parse(config_xml).getroot()
    if not host:
        raise ValueError("Either --host or --config-xml is required.")
    session = SshSession(host, user, port)
    try:
        xml_text = session.run("cat /cf/conf/config.xml")
    finally:
        session.close()
    return ET.fromstring(xml_text)


def load_pfctl_lines(
    pfctl_file: Optional[str],
    host: Optional[str],
    user: str,
    port: int,
) -> List[str]:
    if pfctl_file:
        return Path(pfctl_file).read_text(encoding="utf-8").splitlines()
    if not host:
        return []
    session = SshSession(host, user, port)
    try:
        try:
            output = session.run("pfctl -sr")
        except subprocess.CalledProcessError:
            print("Warning: failed to run pfctl -sr; continuing with config.xml only.", file=sys.stderr)
            return []
        return output.splitlines()
    finally:
        session.close()


def build_dns_rows(root: ET.Element) -> List[Dict[str, str]]:
    entries: Dict[Tuple[str, str], str] = {}

    def add_entry(ip: str, hostname: str, source: str) -> None:
        ip = (ip or "").strip()
        hostname = (hostname or "").strip()
        if not ip or not hostname:
            return
        entries[(ip, hostname)] = source

    def build_hostname(host: str, domain: str) -> str:
        host = (host or "").strip()
        domain = (domain or "").strip()
        if not host:
            return ""
        if domain:
            return f"{host}.{domain}".strip(".")
        return host

    for host in root.findall("./unbound/hosts"):
        ip = host.findtext("ip", default="")
        hostname = build_hostname(host.findtext("host", default=""), host.findtext("domain", default=""))
        add_entry(ip, hostname, "unbound_host_override")
        for alias in host.findall("./aliases/*"):
            alias_name = build_hostname(alias.findtext("host", default=""), alias.findtext("domain", default=""))
            add_entry(ip, alias_name, "unbound_host_alias")

    for host in root.findall("./dnsmasq/hosts/host"):
        ip = host.findtext("ip", default="")
        hostname = build_hostname(host.findtext("host", default=""), host.findtext("domain", default=""))
        add_entry(ip, hostname, "dnsmasq_host_override")
        for alias in host.findall("./aliases/*"):
            alias_name = build_hostname(alias.findtext("host", default=""), alias.findtext("domain", default=""))
            add_entry(ip, alias_name, "dnsmasq_host_alias")

    for section in root.findall("./dhcpd/*"):
        for mapping in section.findall("./staticmap"):
            ip = mapping.findtext("ipaddr", default="")
            hostname = mapping.findtext("hostname", default="")
            add_entry(ip, hostname, "dhcp_static")

    return [
        {"ip": ip, "hostname": hostname}
        for (ip, hostname), _source in sorted(entries.items())
    ]


def build_interface_rows(root: ET.Element) -> List[Dict[str, str]]:
    entries: Dict[str, Tuple[str, str]] = {}

    def add_entry(interface: str, interface_name: str, description: str) -> None:
        interface = (interface or "").strip()
        interface_name = (interface_name or "").strip()
        description = (description or "").strip()
        if not interface:
            return
        if not interface_name:
            interface_name = interface
        if not description:
            description = interface_name
        entries[interface] = (interface_name, description)

    interfaces = root.find("interfaces")
    if interfaces is not None:
        for iface in list(interfaces):
            interface_id = iface.tag or ""
            ifname = iface.findtext("if", default="").strip()
            descr = iface.findtext("descr", default="").strip()
            interface_value = ifname or interface_id
            interface_name = interface_id or ifname
            add_entry(interface_value, interface_name, descr)

    vlans = root.find("vlans")
    if vlans is not None:
        for vlan in vlans.findall("vlan"):
            vlanif = vlan.findtext("vlanif", default="").strip()
            descr = vlan.findtext("descr", default="").strip()
            add_entry(vlanif, vlanif, descr)

    bridges = root.find("bridges")
    if bridges is not None:
        for bridge in bridges.findall("bridge"):
            member = bridge.findtext("members", default="").strip()
            descr = bridge.findtext("descr", default="").strip()
            add_entry(member, member, descr)

    return [
        {
            "interface": interface_value,
            "interface_name": interface_name,
            "interface_description": description,
        }
        for interface_value, (interface_name, description) in sorted(entries.items())
    ]


def build_rule_rows(root: ET.Element, pfctl_lines: List[str]) -> List[Dict[str, str]]:
    def text(node: Optional[ET.Element], path: str) -> str:
        if node is None:
            return ""
        return node.findtext(path, default="").strip()

    def build_endpoint(node: Optional[ET.Element]) -> str:
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

    rows: List[Tuple] = []
    for idx, rule in enumerate(root.findall("./filter/rule"), start=1):
        tracker = text(rule, "tracker")
        if not tracker:
            continue
        descr = text(rule, "descr") or f"rule_{tracker}"
        tracker_numeric = str(int(tracker)) if tracker.isdigit() else ""
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

    def normalize_label(label: str) -> str:
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

    def normalize_proto(value: str) -> str:
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

    def parse_pfctl_summary(lines: List[str]) -> Dict[str, object]:
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

        icmp6_types: Set[str] = set()
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

    def build_standard_name(summary: Dict[str, object], label: Optional[str] = None) -> str:
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

        proto_label = normalize_proto(str(summary["proto"]))
        iface = str(summary["iface"])
        iface_label = "Any"
        if iface.startswith("route-to "):
            iface_label = f"Route-to {iface.split(' ', 1)[1]}"
        elif iface.startswith("on "):
            iface_label = f"On {iface.split(' ', 1)[1]}"

        name = f"System | {action_label} | {direction_label} | {inet_label} | {proto_label} | {iface_label}"
        icmp6_types = summary["icmp6_types"]
        if isinstance(icmp6_types, list) and icmp6_types:
            name = f"{name} ({','.join(icmp6_types)})"
        if label:
            name = f"{name} ({label})"
        return name

    pfctl_by_tracker: Dict[str, Dict[str, List[str]]] = {}
    for line in pfctl_lines:
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

    existing_trackers = {row[1] for row in rows}
    next_rule = len(rows) + 1
    for tracker, data in pfctl_by_tracker.items():
        if tracker in existing_trackers:
            continue
        summary = parse_pfctl_summary(data["lines"])
        label = data["labels"][0] if data["labels"] else ""
        label = build_standard_name(summary, label=label)
        action = str(summary["action"])
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

    rows.sort(key=lambda row: row[0])
    return [dict(zip(RULE_FIELDS, row)) for row in rows]




def _safe_text(elem: Optional[ET.Element], default: str = "") -> str:
    if elem is None or elem.text is None:
        return default
    return elem.text.strip()


def _split_tokens(text: str) -> List[str]:
    return [tok for tok in (text or "").replace(",", " ").split() if tok]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _expand_ports(token: str) -> List[str]:
    if ":" in token:
        start, end = token.split(":", 1)
        try:
            start_i = int(start)
            end_i = int(end)
        except ValueError:
            return []
        if start_i > end_i:
            start_i, end_i = end_i, start_i
        return [str(p) for p in range(start_i, end_i + 1)]
    return [token]


def _normalize_cidr(ipaddr: str, subnet: str) -> str:
    try:
        network = ipaddress.ip_network(f"{ipaddr}/{subnet}", strict=False)
    except ValueError:
        return f"{ipaddr}/{subnet}"
    return str(network)


def parse_enrichment_interfaces(root: ET.Element) -> List[Dict[str, str]]:
    subnet_rows: List[Dict[str, str]] = []

    interfaces = root.find("interfaces")
    if interfaces is None:
        return subnet_rows

    for iface in interfaces:
        name = iface.tag
        descr = _safe_text(iface.find("descr"), name)
        ipaddr = _safe_text(iface.find("ipaddr"))
        subnet = _safe_text(iface.find("subnet"))
        alias_addr = _safe_text(iface.find("alias-address"))
        alias_subnet = _safe_text(iface.find("alias-subnet"))

        if ipaddr and ipaddr.lower() not in ("dhcp", "pppoe"):
            if subnet:
                subnet_rows.append({"cidr": _normalize_cidr(ipaddr, subnet), "zone": descr})

        if alias_addr and alias_subnet:
            subnet_rows.append({"cidr": _normalize_cidr(alias_addr, alias_subnet), "zone": descr})

    return subnet_rows


def spl_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")


def render_spl_import(rows: List[Dict[str, str]], fields: List[str], lookup_name: str) -> str:
    if not rows:
        return "\n".join(
            [
                "| makeresults count=0",
                f"| fields {' '.join(fields)}",
                f"| outputlookup {lookup_name}",
            ]
        )

    lines: List[str] = []
    for idx, row in enumerate(rows):
        eval_parts = []
        for field in fields:
            value = row.get(field, "")
            if value is None:
                value = ""
            eval_parts.append(f'{field}="{spl_escape(str(value))}"')
        eval_clause = ", ".join(eval_parts)
        if idx == 0:
            lines.append(f"| makeresults | eval {eval_clause}")
        else:
            lines.append(f"| append [| makeresults | eval {eval_clause}]")
    lines.append(f"| fields {' '.join(fields)}")
    lines.append(f"| outputlookup {lookup_name}")
    return "\n".join(lines)


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", help="pfSense host or IP")
    parser.add_argument("--user", default="admin", help="SSH user (default: admin)")
    parser.add_argument("--port", default=22, type=int, help="SSH port (default: 22)")
    parser.add_argument("--config-xml", help="Use a local config.xml instead of SSH")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate SPL commands to load pfSense enrichment lookups into KV store.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    dns_parser = subparsers.add_parser("dns", help="Generate DNS host lookups")
    add_common_args(dns_parser)

    interface_parser = subparsers.add_parser("interfaces", help="Generate interface lookups")
    add_common_args(interface_parser)

    rules_parser = subparsers.add_parser("rules", help="Generate rule lookups")
    add_common_args(rules_parser)
    rules_parser.add_argument("--pfctl-file", help="Use a local pfctl -sr output")

    enrichment_parser = subparsers.add_parser(
        "enrichment",
        help="Generate zone subnet enrichment lookups",
    )
    add_common_args(enrichment_parser)

    all_parser = subparsers.add_parser("all", help="Generate all lookups")
    add_common_args(all_parser)
    all_parser.add_argument("--pfctl-file", help="Use a local pfctl -sr output")

    return parser.parse_args()


def validate_source_args(args: argparse.Namespace) -> None:
    if not args.host and not args.config_xml:
        raise SystemExit("Error: --host or --config-xml is required.")


def main() -> None:
    args = parse_args()
    validate_source_args(args)

    if args.command == "dns":
        root = load_config_xml(args.config_xml, args.host, args.user, args.port)
        rows = build_dns_rows(root)
        print(render_spl_import(rows, DNS_FIELDS, "pfsense_dns_hosts"))
        return

    if args.command == "interfaces":
        root = load_config_xml(args.config_xml, args.host, args.user, args.port)
        rows = build_interface_rows(root)
        print(render_spl_import(rows, INTERFACE_FIELDS, "pfsense_interface_map"))
        return

    if args.command == "rules":
        root = load_config_xml(args.config_xml, args.host, args.user, args.port)
        pfctl_lines = load_pfctl_lines(args.pfctl_file, args.host, args.user, args.port)
        rows = build_rule_rows(root, pfctl_lines)
        print(render_spl_import(rows, RULE_FIELDS, "pfsense_filter_rule_map"))
        return

    if args.command == "enrichment":
        root = load_config_xml(args.config_xml, args.host, args.user, args.port)
        rows = parse_enrichment_interfaces(root)
        print(render_spl_import(rows, ZONE_FIELDS, "pfsense_zone_subnets"))
        return

    if args.command == "all":
        root = load_config_xml(args.config_xml, args.host, args.user, args.port)
        pfctl_lines = load_pfctl_lines(args.pfctl_file, args.host, args.user, args.port)
        blocks = [
            render_spl_import(build_dns_rows(root), DNS_FIELDS, "pfsense_dns_hosts"),
            render_spl_import(build_interface_rows(root), INTERFACE_FIELDS, "pfsense_interface_map"),
            render_spl_import(build_rule_rows(root, pfctl_lines), RULE_FIELDS, "pfsense_filter_rule_map"),
            render_spl_import(parse_enrichment_interfaces(root), ZONE_FIELDS, "pfsense_zone_subnets"),
        ]
        print("\n\n".join(blocks))
        return

    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
