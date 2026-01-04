# TA-pfsense Plus

Splunk Technology Add-on for pfSense logs. Provides sourcetypes, parsing,
and lookups for firewall, DNS, VPN, IDS/IPS, and pfBlockerNG data.

## Features

* Parses pfSense logs into structured fields
* Normalizes common fields for dashboards
* Optional lookups for rule names, hostnames, and interfaces

## Sourcetypes

* `pfsense:filterlog`
* `pfsense:filterdns`
* `pfsense:dhcpd`
* `pfsense:kea-dhcp4`
* `pfsense:openvpn`
* `pfsense:nginx`
* `pfsense:unbound`
* `pfsense:snort`
* `pfsense:suricata`
* `pfsense:dnsbl`
* `pfsense:iplog`

## Install

1. Install from Splunkbase, or copy this app to `$SPLUNK_HOME/etc/apps/TA-pfsense-plus`.
2. Restart or reload Splunk.

## Configuration

This TA does not require any specific configuration. Data will be parsed based on
sourcetype assignment. You can send pfSense syslog data to any index.

### Recommended Input Configuration

Configure your pfSense firewall to send syslog data to your Splunk instance:

1. In pfSense: **Status > System Logs > Settings**
2. Enable remote logging
3. Set Splunk server IP/hostname and port (typically 514 or 1514)
4. Configure Splunk inputs.conf to receive the data and assign sourcetype `pfsense`

For UDP inputs, set `no_appending_timestamp = true` to avoid double timestamps.

## CIM Compatibility

This TA provides partial support for the following Common Information Models:

- **Network Traffic**: Firewall events (`pfsense:filterlog`)
- **Authentication**: VPN authentication events (`pfsense:openvpn`)
- **Intrusion Detection**: Snort/Suricata alerts (`pfsense:snort`, `pfsense:suricata`)
- **Network Resolution**: DNS queries (`pfsense:unbound`)

## Contributing

See `CONTRIBUTING.md` for AppInspect and packaging steps.

### Docker install (SPLUNK_APPS_URL)

You can also install via the Splunk Docker image using `SPLUNK_APPS_URL`.

```bash
docker run --name splunk \
  -e "SPLUNK_PASSWORD=<password>" \
  -e "SPLUNK_START_ARGS=--accept-license" \
  -e "SPLUNK_APPS_URL=http://company.com/path/to/app.tgz" \
  -it splunk/splunk:latest
```

## Inputs

This TA expects pfSense syslog data. If you collect via UDP, set
`no_appending_timestamp = true` to avoid double timestamps.

For pfBlockerNG logs:
* DNSBL logs -> `sourcetype=pfsense:dnsbl`
* IP block logs -> `sourcetype=pfsense:iplog`

## Optional: pfBlockerNG logs via syslog-ng

If you want pfBlockerNG-devel logs (DNSBL and IP block), you can use the
pfSense syslog-ng package to forward the files to Splunk.

Create these syslog-ng objects:

Sources:

```
SRC_ip_block
{ file("/var/log/pfblockerng/ip_block.log" flags(no-parse)); };

SRC_dnsbl
{ file("/var/log/pfblockerng/dnsbl.log" flags(no-parse)); };
```

Destinations (replace with your Splunk host IP):

```
DST_ip_block
{ syslog("SPLUNK_IP" transport("udp") port(1516)); };

DST_dnsbl
{ syslog("SPLUNK_IP" transport("udp") port(1515)); };
```

Log paths:

```
LOG_ip_block
{ source(SRC_ip_block); destination(DST_ip_block); };

LOG_dnsbl
{ source(SRC_dnsbl); destination(DST_dnsbl); };
```

Ports used:
* `1515/udp` -> `pfsense:dnsbl`
* `1516/udp` -> `pfsense:iplog`

## Lookup Generators (Optional)

The following helper scripts populate environment-specific lookups by pulling
`/cf/conf/config.xml` over SSH. These scripts live in the repo only and are not
packaged with the Splunk app.

The app ships empty, header-only CSVs so lookups exist even without local
enrichment. Provide real CSVs via the local override at
`$SPLUNK_HOME/etc/apps/ta-pfsense-plus/local/lookup_table_files.conf` when
you want dashboard enrichment.

* `tools/splunk-pfsense-dns-lookup.sh`
  * Output: `lookups/pfsense_dns_hosts.csv`
* `tools/splunk-pfsense-rule-lookup.sh`
  * Output: `lookups/pfsense_filter_rule_map.csv`
* `tools/splunk-pfsense-interface-lookup.sh`
  * Output: `lookups/pfsense_interface_map.csv`

Run them wherever you have SSH access, then load the CSVs into Splunk
using your preferred method (UI upload, app deployment, etc.).

## Notes

* DNSBL and IP log timestamps are parsed from the event payload.
* The lookups are optional; dashboards still work without them.

## Tested Versions

* pfSense: 2.8.1-RELEASE (amd64)
* pfBlockerNG-devel: 3.2.10
* Splunk (Docker): 10.0.2

## Attribution

Based on https://github.com/barakat-abweh/TA-pfsense (Apache-2.0).
See `NOTICE` for attribution details.
