# Blacklisted IP Block Feed

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/denisix/blacklisted-ipblock-feed/update-blocklist.yml)
![GitHub last commit](https://img.shields.io/github/last-commit/denisix/blacklisted-ipblock-feed)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository generates and maintains aggregated IP blocklists from various security threat feeds. It automatically fetches, processes, and optimizes IP ranges from multiple sources to create consolidated blocklists for network security.

## Features

- **Automated Feed Processing**: Fetches IP blocklists from 14 different security feeds
- **Smart Deduplication**: Advanced algorithm that removes overlapping IP ranges and optimizes CIDR blocks
- **Network Aggregation**: Merges individual IPs into /24 networks when 5+ IPs exist in the same subnet
- **Multiple Output Formats**: Individual feed files and combined aggregated list
- **Automated Updates**: GitHub Actions workflow runs every 6 hours to keep feeds current

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
├── source/          # Raw feed data as downloaded
├── dist/            # Processed and deduplicated feeds
│   ├── all.txt      # Combined aggregated blocklist
│   └── *.txt        # Individual processed feeds
├── feeds.json       # Feed source URLs configuration
└── generate.js      # Main processing script
```

## Usage

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
3. Commit updated blocklists to the repository

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
192.168.1.0/24
```

## License

This project aggregates publicly available threat intelligence feeds for defensive security purposes.
