# Blacklisted IP Block Feed

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/denisix/blacklisted-ipblock-feed/update-blocklist.yml)
![GitHub last commit](https://img.shields.io/github/last-commit/denisix/blacklisted-ipblock-feed)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository generates and maintains aggregated IP blocklists from various security threat feeds. It automatically fetches, processes, and optimizes IP ranges from multiple sources to create consolidated blocklists for network security.

## Features

- **Automated Feed Processing**: Fetches IP blocklists from 13 different security feeds
- **Smart Deduplication**: Advanced algorithm that removes overlapping IP ranges and optimizes CIDR blocks
- **Private Network Filtering**: Strips RFC1918 (10/8, 172.16/12, 192.168/16) and other non-routable ranges (loopback, link-local, this-network, CGNAT) from the operational blocklist. Dedicated bogon/special-purpose feeds (`cymru-bogons`, `iana-special-purpose`) retain them.
- **GitHub / Public-Cloud Allowlist**: Fetches GitHub's published ranges from [`api.github.com/meta`](https://api.github.com/meta) and strips any matching IPs from every output feed. This keeps GitHub's own infrastructure — including the broad Azure `actions` ranges that threat feeds frequently flag — out of the blocklist. If the `/meta` request fails, the allowlist is skipped for that run rather than risking stale exclusions.
- **Network Aggregation**: Merges individual IPs into /24 networks when 32+ IPs exist in the same subnet
<<<<<<< HEAD
=======
- **Grouped Combines**: Reads `groups.json` to produce combined files (e.g. `medium.txt`, `brute.txt`) — groups can list feeds explicitly or exclude from the full set
>>>>>>> c4df84c (Add GitHub public-cloud allowlist; raise /24 merge threshold to 32; add grouped combines)
- **Multiple Output Formats**: Individual feed files and combined aggregated list
- **Automated Updates**: GitHub Actions workflow runs every 3 hours and publishes the results to a rolling GitHub Release (the repo itself stays small — generated data is never committed)

## Feed Sources

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
├── groups.json      # Named groups that combine individual feeds into group files
└── generate.js      # Main processing script
```

`source/` and `dist/` are produced by `generate.js` and are **not** committed to the
repository. The processed feeds are published as assets on the rolling
[`latest`](https://github.com/denisix/blacklisted-ipblock-feed/releases/latest) release —
see [Download / Subscribe](#download--subscribe) below.

## Download / Subscribe

The latest feeds are always available at these stable URLs (updated every 3 hours):

- **Combined blocklist**:
  `https://github.com/denisix/blacklisted-ipblock-feed/releases/latest/download/all.txt`
- **Individual feeds**:
  `https://github.com/denisix/blacklisted-ipblock-feed/releases/latest/download/<feed>.txt`
  (e.g. `firehol-level1.txt`, `ipsum.txt`, `cymru-bogons.txt`)
- **Grouped feeds** (defined in `groups.json`):
  `https://github.com/denisix/blacklisted-ipblock-feed/releases/latest/download/<group>.txt`
  (e.g. `medium.txt`, `brute.txt`)

## Groups

`groups.json` defines named combine files produced alongside individual feeds:

| Group   | Description                            | Strategy   |
|---------|----------------------------------------|------------|
| `medium`| All feeds minus ipsum & blocklist-net-ua | `exclude`  |
| `brute` | Brute-force / login attack feeds only  | `feeds`    |

A group can specify its feeds two ways:
- **`feeds`** — explicit list of feed names to include
- **`exclude`** — everything from the full set *except* these names

Both always deduplicate across constituent feeds. Add a new group by editing `groups.json` and pushing — no code changes needed.

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
1. Fetch latest feeds every 3 hours
2. Process and deduplicate IP ranges
3. Publish the processed feeds as assets on the rolling `latest` GitHub Release (the same release is updated in place, so nothing accumulates)

## Algorithm Details

The deduplication process:
1. Fetches GitHub's published IPv4 ranges from `api.github.com/meta` (allowlist)
2. Parses IPs and CIDR blocks from all raw feeds
3. Strips private/RFC1918 ranges from operational feeds (`keepPrivate` feeds retain them)
4. Strips GitHub public-cloud ranges from every feed
5. Groups by network prefix for hierarchical processing
6. Removes subnets contained within larger blocks
7. Merges individual IPs to /24 networks when ≥32 IPs exist in same subnet
8. Writes individual feeds, the combined `all.txt`, and any group files from `groups.json`

## Output Format

All output files contain one IP or CIDR block per line:
```
1.2.3.4
5.6.7.0/24
203.0.113.0/24
```

## License

This project aggregates publicly available threat intelligence feeds for defensive security purposes.
