#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET


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


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_dns_lookup(root: ET.Element, output: Path) -> None:
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

    rows = sorted(((ip, hostname, source) for (ip, hostname), source in entries.items()))

    ensure_parent_dir(output)
    with output.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ip", "hostname", "source"])
        writer.writerows(rows)


def write_interface_lookup(root: ET.Element, output: Path) -> None:
    entries: Dict[str, Tuple[str, str, str]] = {}

    def add_entry(interface: str, description: str, interface_id: str, source: str) -> None:
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

    ensure_parent_dir(output)
    with output.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["interface", "description", "interface_id", "source"])
        writer.writerows(rows)


def write_rule_lookup(root: ET.Element, pfctl_lines: List[str], output: Path) -> None:
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

    ensure_parent_dir(output)
    with output.open("w", newline="") as handle:
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
        writer.writerows(rows)


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


def parse_enrichment_interfaces(root: ET.Element) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    iface_rows: List[Dict[str, str]] = []
    subnet_rows: List[Dict[str, str]] = []

    interfaces = root.find("interfaces")
    if interfaces is None:
        return iface_rows, subnet_rows

    for iface in interfaces:
        name = iface.tag
        descr = _safe_text(iface.find("descr"), name)
        ipaddr = _safe_text(iface.find("ipaddr"))
        subnet = _safe_text(iface.find("subnet"))
        alias_addr = _safe_text(iface.find("alias-address"))
        alias_subnet = _safe_text(iface.find("alias-subnet"))

        if ipaddr and ipaddr.lower() not in ("dhcp", "pppoe"):
            iface_rows.append({"ip": ipaddr, "interface": descr})
            if subnet:
                subnet_rows.append({"cidr": _normalize_cidr(ipaddr, subnet), "zone": descr})

        if alias_addr and alias_subnet:
            iface_rows.append({"ip": alias_addr, "interface": descr})
            subnet_rows.append({"cidr": _normalize_cidr(alias_addr, alias_subnet), "zone": descr})

    return iface_rows, subnet_rows


def parse_enrichment_gateways(root: ET.Element) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    gateways = root.find("gateways")
    if gateways is None:
        return rows
    for gw in gateways.findall("gateway_item"):
        ip = _safe_text(gw.find("gateway"))
        name = _safe_text(gw.find("name"))
        if ip and name:
            rows.append({"ip": ip, "name": name})
    return rows


def write_csv(path: Path, fieldnames: List[str], rows: List[Dict[str, str]]) -> None:
    ensure_parent_dir(path)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(fieldnames)
        for row in rows:
            writer.writerow([row.get(field, "") for field in fieldnames])


def write_enrichment_lookups(root: ET.Element, output_dir: Path) -> None:
    iface_rows, subnet_rows = parse_enrichment_interfaces(root)
    gateway_rows = parse_enrichment_gateways(root)

    write_csv(output_dir / "pfsense_interface_ips_enrichment.csv", ["ip", "interface"], iface_rows)
    write_csv(output_dir / "pfsense_zone_subnets_enrichment.csv", ["cidr", "zone"], subnet_rows)
    write_csv(output_dir / "pfsense_gateway_ips_enrichment.csv", ["ip", "name"], gateway_rows)


def default_output_path(filename: str) -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    return repo_root / "lookups" / filename


def default_output_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "lookups"


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", help="pfSense host or IP")
    parser.add_argument("--user", default="admin", help="SSH user (default: admin)")
    parser.add_argument("--port", default=22, type=int, help="SSH port (default: 22)")
    parser.add_argument("--config-xml", help="Use a local config.xml instead of SSH")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate pfSense Splunk lookup CSVs from config.xml.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    dns_parser = subparsers.add_parser("dns", help="Generate DNS host lookups")
    add_common_args(dns_parser)
    dns_parser.add_argument(
        "--output",
        default=str(default_output_path("pfsense_dns_hosts_enrichment.csv")),
        help="Output CSV path",
    )

    interface_parser = subparsers.add_parser("interfaces", help="Generate interface lookups")
    add_common_args(interface_parser)
    interface_parser.add_argument(
        "--output",
        default=str(default_output_path("pfsense_interface_map_enrichment.csv")),
        help="Output CSV path",
    )

    rules_parser = subparsers.add_parser("rules", help="Generate rule lookups")
    add_common_args(rules_parser)
    rules_parser.add_argument("--pfctl-file", help="Use a local pfctl -sr output")
    rules_parser.add_argument(
        "--output",
        default=str(default_output_path("pfsense_filter_rule_map_enrichment.csv")),
        help="Output CSV path",
    )

    enrichment_parser = subparsers.add_parser(
        "enrichment",
        help="Generate zone/gateway/interface IP enrichment lookups",
    )
    add_common_args(enrichment_parser)
    enrichment_parser.add_argument(
        "--output-dir",
        default=str(default_output_dir()),
        help="Directory to write enrichment CSVs",
    )

    all_parser = subparsers.add_parser("all", help="Generate all lookups")
    add_common_args(all_parser)
    all_parser.add_argument("--pfctl-file", help="Use a local pfctl -sr output")
    all_parser.add_argument(
        "--output-dir",
        default=str(default_output_dir()),
        help="Directory to write lookup CSVs",
    )

    return parser.parse_args()


def validate_source_args(args: argparse.Namespace) -> None:
    if not args.host and not args.config_xml:
        raise SystemExit("Error: --host or --config-xml is required.")


def main() -> None:
    args = parse_args()
    validate_source_args(args)

    if args.command == "dns":
        root = load_config_xml(args.config_xml, args.host, args.user, args.port)
        output = Path(args.output)
        write_dns_lookup(root, output)
        print(f"Wrote lookup: {output}")
        return

    if args.command == "interfaces":
        root = load_config_xml(args.config_xml, args.host, args.user, args.port)
        output = Path(args.output)
        write_interface_lookup(root, output)
        print(f"Wrote lookup: {output}")
        return

    if args.command == "rules":
        root = load_config_xml(args.config_xml, args.host, args.user, args.port)
        pfctl_lines = load_pfctl_lines(args.pfctl_file, args.host, args.user, args.port)
        output = Path(args.output)
        write_rule_lookup(root, pfctl_lines, output)
        print(f"Wrote lookup: {output}")
        return

    if args.command == "enrichment":
        root = load_config_xml(args.config_xml, args.host, args.user, args.port)
        output_dir = Path(args.output_dir)
        write_enrichment_lookups(root, output_dir)
        print(f"Wrote enrichment lookups to: {output_dir}")
        return

    if args.command == "all":
        root = load_config_xml(args.config_xml, args.host, args.user, args.port)
        pfctl_lines = load_pfctl_lines(args.pfctl_file, args.host, args.user, args.port)
        output_dir = Path(args.output_dir)
        write_dns_lookup(root, output_dir / "pfsense_dns_hosts_enrichment.csv")
        write_interface_lookup(root, output_dir / "pfsense_interface_map_enrichment.csv")
        write_rule_lookup(root, pfctl_lines, output_dir / "pfsense_filter_rule_map_enrichment.csv")
        write_enrichment_lookups(root, output_dir)
        print(f"Wrote lookups to: {output_dir}")
        return

    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
