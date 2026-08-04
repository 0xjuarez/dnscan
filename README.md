# dnscan

> OSINT-first reconnaissance tool for IP addresses and domain names.
> Passive by default. Active scanning only when explicitly requested.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-stable-success)

---

## Overview

dnscan is a lightweight reconnaissance utility focused on collecting information about IP addresses and domains.

Unlike traditional scanners, **dnscan is passive by default**. It gathers intelligence from public OSINT sources without directly interacting with the target.

Only the `--scan-all` option performs active TCP connections.

The project has **zero external dependencies** and relies entirely on Python's standard library.

---

## Features

### Passive Recon (Default)

- RDAP ownership information
- ASN / BGP lookup (Team Cymru)
- GeoIP information
- Reverse DNS lookup
- Shodan InternetDB lookup
- Certificate Transparency search (crt.sh)
- Automatic IP scope detection
- IPv4 resolution

### Optional Enrichment

- CVE correlation
- VirusTotal reputation
- AbuseIPDB reputation
- API key validation

### Active Mode

Only enabled with:

```bash
--scan-all
```

Features:

- TCP Connect Scan
- Custom port ranges
- Banner grabbing
- Configurable concurrency

---

## Installation

Clone the repository.

```bash
git clone https://github.com/YOUR_USERNAME/dnscan.git

cd dnscan
```

No dependencies are required.

```
Python 3.10+
```

---

## Usage

Basic lookup

```bash
python3 dnscan.py 1.1.1.1
```

Domain lookup

```bash
python3 dnscan.py example.com
```

JSON output

```bash
python3 dnscan.py example.com --format json
```

Markdown report

```bash
python3 dnscan.py example.com --format markdown
```

Full passive enrichment

```bash
python3 dnscan.py example.com --full
```

Active scan

```bash
python3 dnscan.py example.com --scan-all
```

Custom ports

```bash
python3 dnscan.py example.com --scan-all --ports 1-1024,8080,8443
```

Check configured API Keys

```bash
python3 dnscan.py --check-keys
```

---

## Output Formats

- Table (default)
- JSON
- Markdown

---

## API Keys

Optional modules require API keys.

Supported services:

- VirusTotal
- AbuseIPDB
- Shodan (validation only)

They can be configured through environment variables:

```bash
export VT_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export SHODAN_API_KEY="..."
```

or via CLI arguments.

---

## Passive vs Active

| Module | Passive |
|---------|----------|
| RDAP | ✅ |
| ASN | ✅ |
| GeoIP | ✅ |
| Reverse DNS | ✅ |
| crt.sh | ✅ |
| Shodan InternetDB | ✅ |
| VirusTotal | ✅ |
| AbuseIPDB | ✅ |
| CVE Correlation | ✅ |
| TCP Scan | ❌ Active |

---

## Why dnscan?

Many reconnaissance tools immediately interact with the target.

dnscan follows a different philosophy:

- Passive first
- OSINT focused
- Zero dependencies
- Fast
- Easy to automate
- Structured output
- Optional active scanning

---

## Disclaimer

Use this software only against systems you own or are explicitly authorized to test.

The passive modules query third-party public services.

The active scanning mode (`--scan-all`) establishes direct TCP connections to the target.

The user is responsible for complying with all applicable laws and regulations.

---

## Roadmap

- IPv6 support
- Plugin system
- Local cache
- Additional OSINT providers
- HTML reports
- Docker image

---

## License

MIT License.
