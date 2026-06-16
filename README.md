# Blacklisted IP Block Feed

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/denisix/blacklisted-ipblock-feed/update-blocklist.yml)
![GitHub last commit](https://img.shields.io/github/last-commit/denisix/blacklisted-ipblock-feed)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository generates and maintains aggregated IP blocklists from various security threat feeds. It automatically fetches, processes, and optimizes IP ranges from multiple sources to create consolidated blocklists for network security.

## Features

- **Automated Feed Processing**: Fetches IP blocklists from 14 different security feeds
- **Smart Deduplication**: Advanced algorithm that removes overlapping IP ranges and optimizes CIDR blocks
- **Private Network Filtering**: Strips RFC1918 (10/8, 172.16/12, 192.168/16) and other non-routable ranges (loopback, link-local, this-network, CGNAT) from the operational blocklist. Dedicated bogon/special-purpose feeds (`cymru-bogons`, `iana-special-purpose`) retain them.
- **Network Aggregation**: Merges individual IPs into /24 networks when 5+ IPs exist in the same subnet
- **Multiple Output Formats**: Individual feed files and combined aggregated list
- **Automated Updates**: GitHub Actions workflow runs every 6 hours and publishes the results to a rolling GitHub Release (the repo itself stays small — generated data is never committed)

## Feeds Sources

The system aggregates data from these security feeds:

- **abuse.ch Feodo Tracker** - Banking trojan C&C servers
- **blocklist.de** - SSH brute force and login attack IPs
- **blocklist.net.ua** - Ukrainian blocklist
- **BruteForceBlocker** - SSH/FTP brute force attempts
- **CI Army** - Collective Intelligence malicious IPs
- **Team Cymru Bogons** - Non-routable IP addresses
- **Emerging Threats** - Spamhaus and other threat intel
- **FireHOL Level1** - High-confidence malicious IPs
- **IANA Special Purpose** - Reserved/special use addresses
- **IPsum** - Daily updated threat intelligence
- **URLhaus** - Malware hosting domains/IPs

## Directory Structure

```
├── source/          # Raw feed data as downloaded — generated, gitignored
├── dist/            # Processed and deduplicated feeds — generated, gitignored
│   ├── all.txt      # Combined aggregated blocklist
│   └── *.txt        # Individual processed feeds
├── feeds.json       # Feed source URLs configuration
└── generate.js      # Main processing script
```

`source/` and `dist/` are produced by `generate.js` and are **not** committed to the
repository. The processed feeds are published as assets on the rolling
[`latest`](https://github.com/denisix/blacklisted-ipblock-feed/releases/latest) release —
see [Download / Subscribe](#download--subscribe) below.

## Download / Subscribe

The latest feeds are always available at these stable URLs (updated every 6 hours):

- **Combined blocklist**:
  `https://github.com/denisix/blacklisted-ipblock-feed/releases/latest/download/all.txt`
- **Individual feeds**:
  `https://github.com/denisix/blacklisted-ipblock-feed/releases/latest/download/<feed>.txt`
  (e.g. `firehol-level1.txt`, `ipsum.txt`, `cymru-bogons.txt`)

## Usage

### VyOS firewall

Point a network-group at the combined feed and drop traffic from it:

```bash
set firewall group network-group blacklisted-ipblock-feed url 'https://github.com/denisix/blacklisted-ipblock-feed/releases/latest/download/all.txt'
set firewall ipv4 forward filter rule 31 action 'drop'
set firewall ipv4 forward filter rule 31 source group network-group 'blacklisted-ipblock-feed'
```

### Manual Generation

```bash
bun run generate.js
# or
node generate.js
```

### Automated Updates

The repository uses GitHub Actions to automatically:
1. Fetch latest feeds every 6 hours
2. Process and deduplicate IP ranges
3. Publish the processed feeds as assets on the rolling `latest` GitHub Release (the same release is updated in place, so nothing accumulates)

## Algorithm Details

The deduplication process:
1. Parses IPs and CIDR blocks from raw feeds
2. Groups by network prefix for hierarchical processing  
3. Removes subnets contained within larger blocks
4. Merges individual IPs to /24 networks when ≥5 IPs exist in same subnet
5. Outputs optimized, non-overlapping IP ranges

## Output Format

All output files contain one IP or CIDR block per line:
```
1.2.3.4
5.6.7.0/24
203.0.113.0/24
```

## License

This project aggregates publicly available threat intelligence feeds for defensive security purposes.
