# dnscan — Advanced DNS Reconnaissance

`dnscan` is a single-file, standard-library-only DNS reconnaissance tool.
No third-party dependencies: it speaks the DNS wire protocol directly
(UDP with TCP fallback) using only Python's `socket` and `struct`.

```text
$ python3 dnscan.py example.com
dnscan 1.0.0  —  example.com
Scanned at 2026-11-11T20:00:00+00:00 (UTC) via 1.1.1.1, 8.8.8.8, 9.9.9.9

== A records ==
  93.184.216.34  (TTL 3600)

== MX records ==
  mail.example.com (pref 10)  (TTL 3600)
```

## Features

- **DNS records** — A, AAAA, MX, NS, TXT, SOA, CAA, DNSKEY, DS, and
  SRV (with `--srv`), plus PTR/reverse lookups, via a hand-rolled DNS
  client (UDP, TCP fallback on truncation or UDP failure).
- **Multiple resolvers** — system resolvers from `/etc/resolv.conf`,
  plus 1.1.1.1, 8.8.8.8 and 9.9.9.9; override with `--resolver`
  (repeatable), `--timeout` and `--retries`.
- **Email authentication** — SPF (`v=spf1`) analysis from TXT records,
  DMARC (`_dmarc.<domain>`), and DKIM via opt-in `--dkim-selector`
  (no selector brute-forcing).
- **DNSSEC presence** — reports whether DNSKEY / DS / RRSIG records
  exist for the zone.
- **Zone transfer (AXFR)** — only behind the opt-in `--axfr` flag;
  refused / successful / error outcomes are reported clearly.
- **Wildcard detection** — a random non-existent label is queried
  before subdomain enumeration; if it resolves, results are flagged
  as possible wildcard noise.
- **Subdomain enumeration** — built-in wordlist of 110+ common labels,
  or a custom list with `--wordlist`; concurrent probes
  (`--threads`, default 10) with optional `--delay` rate limiting.
- **Reverse DNS** for every discovered IP.
- **WHOIS** (port 43) with IANA → RIR referral following; a WHOIS
  failure never crashes the scan.
- **ASN / organisation** via Team Cymru DNS
  (`<reversed-ip>.origin.asn.cymru.com`).
- **Output** — coloured human-readable text (`--no-color` to disable),
  `--json`, `--csv`, and `-o/--output` to save to a file.
- **Targets** — a hostname (IDNA/punycode handled) or an IPv4 address.
  Invalid input exits with a clear usage error.

## Install

None. Python 3.9+ and nothing else:

```sh
git clone https://github.com/0xjuarez/dnscan.git
cd dnscan
python3 dnscan.py --help
```

## Usage

```sh
# Basic scan of a domain
python3 dnscan.py example.com

# JSON report saved to a file
python3 dnscan.py example.com --json -o report.json

# CSV output
python3 dnscan.py example.com --csv -o report.csv

# Use specific resolvers
python3 dnscan.py example.com --resolver 1.1.1.1 --resolver 8.8.8.8

# Custom wordlist, more threads, gentle rate limiting
python3 dnscan.py example.com --wordlist mylist.txt --threads 20 --delay 0.1

# Check a DKIM selector and try a zone transfer (active — needs authorization)
python3 dnscan.py example.com --dkim-selector default --axfr

# Scan an IP address (reverse DNS, ASN, WHOIS)
python3 dnscan.py 8.8.8.8

# Fast passive-only scan (no subdomain enumeration, no WHOIS)
python3 dnscan.py example.com --no-enum --no-whois
```

Exit codes: `0` success, `2` usage error, `1` runtime failure
(e.g. no resolver reachable).

## Passive vs. active

| Check | Kind | Needs authorization? |
|---|---|---|
| DNS record queries (A, AAAA, MX, NS, TXT, SOA, CAA, DNSKEY, DS, SRV) | Passive | No — public DNS queries |
| SPF / DMARC / DKIM analysis | Passive | No |
| DNSSEC presence | Passive | No |
| Reverse DNS, ASN (Team Cymru), WHOIS | Passive | No |
| Subdomain enumeration | **Active** | **Yes** — it sends many queries for labels that may not exist |
| Zone transfer (AXFR) | **Active** | **Yes** — opt-in with `--axfr` only |

## Legal note

Only scan domains you own or are authorized to test. Subdomain
enumeration and zone-transfer attempts generate noticeable traffic
against the target's infrastructure; running them against systems
without permission may violate the law and the target's policies.
The author is not responsible for misuse of this tool.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
