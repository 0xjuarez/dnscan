#!/usr/bin/env python3
"""dnscan - Advanced passive DNS reconnaissance tool.

Single-file, standard-library-only DNS recon: query DNS records with a
hand-rolled DNS wire-protocol client (UDP with TCP fallback), analyse
email authentication (SPF / DMARC / DKIM), check DNSSEC presence,
detect wildcards, enumerate subdomains, resolve reverse DNS, look up
ASN data (Team Cymru) and WHOIS information.

Passive by design: every query goes to a DNS resolver, to Team Cymru's
DNS, or to a WHOIS server on port 43. Two checks are active and need
authorization on the target: subdomain enumeration and the optional
zone-transfer (AXFR) attempt. Only scan domains you own or are
authorized to test.

Usage:
    python3 dnscan.py example.com
    python3 dnscan.py example.com --json -o report.json
    python3 dnscan.py example.com --axfr --dkim-selector default

Exit codes: 0 ok, 2 usage error, 1 runtime failure.
"""

import argparse
import csv
import io
import json
import re
import secrets
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"
__author__ = "Jesus Alejandro Juarez Contreras"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: DNS record type codes we understand.
RTYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
    "TXT": 16, "AAAA": 28, "SRV": 33, "DS": 43, "RRSIG": 46,
    "DNSKEY": 48, "CAA": 257, "AXFR": 252,
}
RTYPE_NAMES = {code: name for name, code in RTYPES.items()}

#: RCODE values from RFC 1035.
RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
    8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}

#: Default resolvers tried in order when --resolver is not given.
DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

#: DNS port.
DNS_PORT = 53

#: Maximum DNS message size we accept over TCP.
MAX_TCP_SIZE = 65535

#: Common SRV services queried with --srv.
SRV_SERVICES = [
    "_sip._tcp", "_sip._tls", "_xmpp-client._tcp", "_xmpp-server._tcp",
    "_ldap._tcp", "_kerberos._tcp", "_kerberos._udp",
    "_autodiscover._tcp", "_caldav._tcp", "_carddav._tcp",
]

#: Built-in subdomain wordlist (~110 common labels).
BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "ns", "dns", "mx", "mx1", "mx2", "blog", "shop", "store", "api",
    "dev", "staging", "test", "admin", "portal", "vpn", "remote",
    "secure", "login", "app", "apps", "cdn", "static", "media", "images",
    "video", "support", "help", "docs", "wiki", "forum", "chat", "git",
    "svn", "jira", "confluence", "crm", "erp", "intranet", "extranet",
    "gateway", "proxy", "firewall", "backup", "db", "database", "mysql",
    "postgres", "sql", "monitor", "nagios", "zabbix", "grafana", "kibana",
    "log", "logs", "status", "cloud", "s3", "edge", "cache", "search",
    "analytics", "metrics", "tracker", "ads", "web", "site", "home",
    "main", "m", "mobile", "beta", "alpha", "demo", "sandbox", "internal",
    "private", "public", "www2", "www3", "mail2", "mail3", "exchange",
    "owa", "webdisk", "cpanel", "whm", "direct", "panel", "dashboard",
    "console", "auth", "sso", "idp", "ldap", "sip", "voip", "pbx",
    "files", "drive", "share", "download", "upload", "assets",
]

#: Hostname label rules (RFC 1034/1035, ASCII after IDNA conversion).
_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class DNSError(Exception):
    """Raised when a DNS query fails on every resolver."""


class UsageError(Exception):
    """Raised for invalid user input (exit code 2)."""


# ---------------------------------------------------------------------------
# Output colours
# ---------------------------------------------------------------------------

class Colors:
    """ANSI colour helpers; disabled with --no-color or non-TTY output."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return "\033[%sm%s\033[0m" % (code, text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)


# ---------------------------------------------------------------------------
# DNS wire protocol (RFC 1035)
# ---------------------------------------------------------------------------

def encode_name(name: str) -> bytes:
    """Encode a domain name into DNS wire format (length-prefixed labels)."""
    if name in ("", "."):
        return b"\x00"
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise ValueError("DNS label too long: %r" % label)
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def decode_name(message: bytes, offset: int) -> Tuple[str, int]:
    """Decode a (possibly compressed) domain name from a DNS message.

    Returns the dotted name and the offset just past the name in the
    original stream (i.e. after the 2-byte pointer when compression is
    used). Raises ValueError on malformed data or pointer loops.
    """
    labels = []
    jumped = False
    next_offset = offset
    jumps = 0
    while True:
        if offset >= len(message):
            raise ValueError("name extends past end of message")
        length = message[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            # Compression pointer: 14-bit offset into the message.
            if offset + 1 >= len(message):
                raise ValueError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if not jumped:
                next_offset = offset + 2
            jumps += 1
            if jumps > 10:
                raise ValueError("too many compression jumps")
            offset = pointer
            jumped = True
            continue
        if length & 0xC0:
            raise ValueError("invalid label length byte 0x%02x" % length)
        offset += 1
        if offset + length > len(message):
            raise ValueError("label extends past end of message")
        labels.append(message[offset:offset + length].decode("ascii", "replace"))
        offset += length
        if not jumped:
            next_offset = offset
    return ".".join(labels), next_offset


def build_query(name: str, qtype: int, query_id: Optional[int] = None) -> bytes:
    """Build a standard DNS query (recursion desired) for name/qtype."""
    if query_id is None:
        query_id = secrets.randbits(16)
    flags = 0x0100  # RD set
    header = struct.pack(">HHHHHH", query_id, flags, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack(">HH", qtype, 1)  # QCLASS IN
    return header + question


def _parse_rdata(rtype: int, rdata: bytes, message: bytes,
                 rdata_offset: int) -> object:
    """Parse the RDATA of one resource record into a Python value."""
    if rtype == 1:  # A
        if len(rdata) != 4:
            raise ValueError("bad A record length")
        return socket.inet_ntoa(rdata)
    if rtype == 28:  # AAAA
        if len(rdata) != 16:
            raise ValueError("bad AAAA record length")
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (2, 5, 12):  # NS, CNAME, PTR
        name, _ = decode_name(message, rdata_offset)
        return name
    if rtype == 15:  # MX
        preference = struct.unpack(">H", rdata[:2])[0]
        exchange, _ = decode_name(message, rdata_offset + 2)
        return {"preference": preference, "exchange": exchange}
    if rtype == 16:  # TXT
        parts = []
        pos = 0
        while pos < len(rdata):
            size = rdata[pos]
            parts.append(rdata[pos + 1:pos + 1 + size].decode("utf-8", "replace"))
            pos += 1 + size
        return parts
    if rtype == 6:  # SOA
        mname, off = decode_name(message, rdata_offset)
        rname, off = decode_name(message, off)
        serial, refresh, retry, expire, minimum = struct.unpack(
            ">IIIII", rdata[off - rdata_offset:off - rdata_offset + 20])
        return {
            "mname": mname, "rname": rname, "serial": serial,
            "refresh": refresh, "retry": retry, "expire": expire,
            "minimum": minimum,
        }
    if rtype == 33:  # SRV
        priority, weight, port = struct.unpack(">HHH", rdata[:6])
        target, _ = decode_name(message, rdata_offset + 6)
        return {"priority": priority, "weight": weight, "port": port,
                "target": target}
    if rtype == 257:  # CAA
        flags = rdata[0]
        tag_len = rdata[1]
        tag = rdata[2:2 + tag_len].decode("ascii", "replace")
        value = rdata[2 + tag_len:].decode("utf-8", "replace")
        return {"flags": flags, "tag": tag, "value": value}
    if rtype == 48:  # DNSKEY
        flags, protocol, algorithm = struct.unpack(">HBB", rdata[:4])
        return {"flags": flags, "protocol": protocol, "algorithm": algorithm,
                "key_bytes": len(rdata) - 4}
    if rtype == 43:  # DS
        key_tag, algorithm, digest_type = struct.unpack(">HBB", rdata[:4])
        return {"key_tag": key_tag, "algorithm": algorithm,
                "digest_type": digest_type, "digest": rdata[4:].hex()}
    if rtype == 46:  # RRSIG
        (covered, algorithm, labels, orig_ttl, expiration, inception,
         key_tag) = struct.unpack(">HBBIIIH", rdata[:18])
        signer, _ = decode_name(message, rdata_offset + 18)
        return {"type_covered": RTYPE_NAMES.get(covered, str(covered)),
                "algorithm": algorithm, "labels": labels,
                "original_ttl": orig_ttl, "expiration": expiration,
                "inception": inception, "key_tag": key_tag,
                "signer": signer}
    # Unknown type: return raw bytes as hex.
    return rdata.hex()


def parse_message(data: bytes) -> Dict[str, object]:
    """Parse a raw DNS response message into a structured dict.

    Returns keys: id, flags, rcode, truncated, questions, answers,
    authority, additional. Each section entry is a dict with at least
    name/type/type_name/class/ttl and a parsed ``value`` for RRs.
    """
    if len(data) < 12:
        raise ValueError("DNS message too short (%d bytes)" % len(data))
    (msg_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack(
        ">HHHHHH", data[:12])
    offset = 12
    questions = []
    for _ in range(qdcount):
        qname, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError("truncated question section")
        qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
        offset += 4
        questions.append({"name": qname, "type": qtype,
                          "type_name": RTYPE_NAMES.get(qtype, str(qtype)),
                          "class": qclass})
    sections = {"answers": [], "authority": [], "additional": []}
    counts = {"answers": ancount, "authority": nscount, "additional": arcount}
    for section, count in counts.items():
        for _ in range(count):
            name, offset = decode_name(data, offset)
            if offset + 10 > len(data):
                raise ValueError("truncated resource record")
            rtype, rclass, ttl, rdlen = struct.unpack(
                ">HHIH", data[offset:offset + 10])
            offset += 10
            if offset + rdlen > len(data):
                raise ValueError("RDATA extends past end of message")
            rdata = data[offset:offset + rdlen]
            try:
                value = _parse_rdata(rtype, rdata, data, offset)
            except (ValueError, struct.error, IndexError):
                value = rdata.hex()
            sections[section].append({
                "name": name, "type": rtype,
                "type_name": RTYPE_NAMES.get(rtype, str(rtype)),
                "class": rclass, "ttl": ttl, "value": value,
            })
            offset += rdlen
    return {
        "id": msg_id, "flags": flags, "rcode": flags & 0x000F,
        "rcode_name": RCODES.get(flags & 0x000F, "UNKNOWN"),
        "truncated": bool(flags & 0x0200),
        "questions": questions,
        "answers": sections["answers"],
        "authority": sections["authority"],
        "additional": sections["additional"],
    }


# ---------------------------------------------------------------------------
# DNS resolver (UDP with TCP fallback)
# ---------------------------------------------------------------------------

class Resolver:
    """Minimal recursive DNS resolver over UDP, falling back to TCP.

    Tries each configured server in order, with per-query timeout and
    retries. Only speaks to the servers the user configured (plus the
    system default from /etc/resolv.conf when no server is given).
    """

    def __init__(self, servers: Optional[List[str]] = None,
                 timeout: float = 5.0, retries: int = 2):
        self.servers = servers or _system_resolvers() or DEFAULT_RESOLVERS
        self.timeout = timeout
        self.retries = retries

    def query(self, name: str, qtype: int) -> Dict[str, object]:
        """Send one query; return the parsed response message.

        UDP first; TCP is used when the response is truncated (TC bit)
        or when UDP itself fails (e.g. a network that blocks UDP).
        Raises DNSError if every server fails or times out.
        """
        query = build_query(name, qtype)
        errors = []
        for server in self.servers:
            for _attempt in range(self.retries + 1):
                try:
                    raw = self._exchange_udp(server, query)
                except (socket.timeout, socket.error) as exc:
                    errors.append("%s (UDP): %s" % (server, exc))
                    try:
                        raw = self._exchange_tcp(server, query)
                    except (socket.timeout, socket.error, ValueError) as exc2:
                        errors.append("%s (TCP): %s" % (server, exc2))
                        continue
                try:
                    response = parse_message(raw)
                except ValueError as exc:
                    errors.append("%s: %s" % (server, exc))
                    continue
                if response["truncated"]:
                    try:
                        raw = self._exchange_tcp(server, query)
                        response = parse_message(raw)
                    except (socket.timeout, socket.error, ValueError) as exc:
                        errors.append("%s (TCP): %s" % (server, exc))
                        continue
                return response
        raise DNSError("query %s/%s failed on all resolvers (%s)"
                       % (name, RTYPE_NAMES.get(qtype, qtype),
                          "; ".join(errors)))

    def query_records(self, name: str, qtype: int) -> List[Dict[str, object]]:
        """Return answer records for name/qtype, following CNAME chains.

        A NXDOMAIN or an empty answer yields an empty list (no exception);
        transport failures still raise DNSError.
        """
        records: List[Dict[str, object]] = []
        current = name
        for _hop in range(4):
            response = self.query(current, qtype)
            if response["rcode"] == 3:  # NXDOMAIN
                return records
            answers = response["answers"]
            if not answers:
                return records
            cnames = [r for r in answers if r["type"] == 5]
            wanted = [r for r in answers if r["type"] == qtype]
            records.extend(wanted)
            if wanted or not cnames:
                return records
            current = str(cnames[0]["value"])
        return records

    def _exchange_udp(self, server: str, query: bytes) -> bytes:
        """Send a query over UDP and return the raw response bytes."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.timeout)
            sock.sendto(query, (server, DNS_PORT))
            data, _addr = sock.recvfrom(4096)
            return data
        finally:
            sock.close()

    def _exchange_tcp(self, server: str, query: bytes) -> bytes:
        """Send a query over TCP (2-byte length prefix) and return bytes."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((server, DNS_PORT))
            sock.sendall(struct.pack(">H", len(query)) + query)
            length_bytes = _recv_exact(sock, 2)
            (length,) = struct.unpack(">H", length_bytes)
            if length > MAX_TCP_SIZE:
                raise ValueError("TCP response too large: %d" % length)
            return _recv_exact(sock, length)
        finally:
            sock.close()

    def axfr(self, nameserver: str, zone: str) -> Dict[str, object]:
        """Attempt a zone transfer (AXFR) from one nameserver over TCP.

        Returns {"status": "success"|"refused"|"error", "records": [...],
        "message": str}. Callers must gate this behind --axfr.
        """
        query = build_query(zone, RTYPES["AXFR"])
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((nameserver, DNS_PORT))
            sock.sendall(struct.pack(">H", len(query)) + query)
            records: List[Dict[str, object]] = []
            saw_soa = 0
            for _ in range(200):  # safety cap on message count
                length_bytes = _recv_exact(sock, 2)
                (length,) = struct.unpack(">H", length_bytes)
                data = _recv_exact(sock, length)
                response = parse_message(data)
                if response["rcode"] != 0:
                    return {"status": "refused", "records": [],
                            "message": "server replied %s"
                                       % response["rcode_name"]}
                records.extend(response["answers"])
                saw_soa += sum(1 for r in response["answers"]
                               if r["type"] == 6)
                if saw_soa >= 2:
                    break
            sock.close()
            return {"status": "success", "records": records,
                    "message": "%d records received" % len(records)}
        except (socket.timeout, socket.error, ValueError, struct.error) as exc:
            return {"status": "error", "records": [],
                    "message": "AXFR failed: %s" % exc}


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    """Read exactly ``count`` bytes from a TCP socket."""
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ValueError("connection closed early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _system_resolvers() -> List[str]:
    """Read IPv4 nameservers from /etc/resolv.conf (empty on failure).

    Only IPv4 is returned: this resolver speaks AF_INET, so an IPv6
    nameserver could never be used and would only add noise.
    """
    servers = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    candidate = parts[1]
                    try:
                        socket.inet_aton(candidate)
                    except OSError:
                        continue  # IPv6 or invalid: skip
                    servers.append(candidate)
    except OSError:
        pass
    return servers


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

def normalize_target(raw: str) -> Tuple[str, str]:
    """Validate and normalize a scan target.

    Returns (ascii_target, kind) where kind is "domain" or "ipv4".
    Handles IDNA/punycode for internationalised names. Raises
    UsageError for empty or invalid input.
    """
    target = (raw or "").strip().rstrip(".")
    if not target:
        raise UsageError("empty target: pass a domain or IPv4 address")
    # IPv4 address.
    parts = target.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        octets = [int(p) for p in parts]
        if all(0 <= o <= 255 for o in octets) and all(
                p == str(int(p)) for p in parts):
            return target, "ipv4"
        raise UsageError("invalid IPv4 address: %r" % raw)
    # Hostname (IDNA -> ASCII punycode).
    try:
        ascii_target = target.encode("idna").decode("ascii")
    except UnicodeError:
        raise UsageError("invalid domain name: %r" % raw)
    if len(ascii_target) > 253:
        raise UsageError("domain name too long: %r" % raw)
    for label in ascii_target.split("."):
        if not _LABEL_RE.match(label):
            raise UsageError("invalid domain label %r in %r" % (label, raw))
    return ascii_target.lower(), "domain"


# ---------------------------------------------------------------------------
# Email authentication analysis (SPF / DMARC / DKIM)
# ---------------------------------------------------------------------------

def parse_spf(txt_values: List[str]) -> Optional[Dict[str, object]]:
    """Parse an SPF record from the domain's TXT records."""
    for value in txt_values:
        text = value.strip().strip('"')
        if not text.startswith("v=spf1"):
            continue
        tokens = text.split()
        result: Dict[str, object] = {
            "record": text, "includes": [], "ip4": [], "ip6": [],
            "mechanisms": [], "all": None, "redirect": None,
        }
        for token in tokens[1:]:
            if token.startswith("include:"):
                result["includes"].append(token.split(":", 1)[1])
            elif token.startswith("ip4:"):
                result["ip4"].append(token.split(":", 1)[1])
            elif token.startswith("ip6:"):
                result["ip6"].append(token.split(":", 1)[1])
            elif token.startswith("redirect="):
                result["redirect"] = token.split("=", 1)[1]
            elif token in ("-all", "~all", "?all", "+all"):
                result["all"] = token
            else:
                result["mechanisms"].append(token)
        return result
    return None


def parse_dmarc(txt_values: List[str]) -> Optional[Dict[str, object]]:
    """Parse a DMARC record (TXT at _dmarc.<domain>)."""
    for value in txt_values:
        text = value.strip().strip('"')
        if not text.startswith("v=DMARC1"):
            continue
        fields: Dict[str, str] = {}
        for part in text.split(";"):
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                fields[key.strip()] = val.strip()
        return {
            "record": text, "policy": fields.get("p"),
            "subdomain_policy": fields.get("sp"),
            "pct": fields.get("pct"),
            "rua": fields.get("rua"), "ruf": fields.get("ruf"),
            "adkim": fields.get("adkim"), "aspf": fields.get("aspf"),
        }
    return None


def parse_dkim(txt_values: List[str]) -> Optional[Dict[str, object]]:
    """Parse a DKIM record (TXT at <selector>._domainkey.<domain>)."""
    for value in txt_values:
        text = value.strip().strip('"')
        if "v=DKIM1" not in text:
            continue
        fields: Dict[str, str] = {}
        for part in text.split(";"):
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                fields[key.strip()] = val.strip()
        public_key = fields.get("p", "")
        return {
            "record": text, "version": fields.get("v"),
            "key_type": fields.get("k"), "hash_algorithms": fields.get("h"),
            "public_key_preview": (public_key[:40] + "..."
                                   if len(public_key) > 40 else public_key),
            "public_key_length": len(public_key),
        }
    return None


# ---------------------------------------------------------------------------
# WHOIS (port 43) and ASN (Team Cymru)
# ---------------------------------------------------------------------------

def _whois_query(server: str, query: str, timeout: float) -> str:
    """Send one WHOIS query over TCP port 43 and return the raw text."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((server, 43))
        sock.sendall((query + "\r\n").encode("utf-8", "replace"))
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        sock.close()
    return b"".join(chunks).decode("utf-8", "replace")


def _find_referral(text: str) -> Optional[str]:
    """Extract a 'whois:' referral server from a WHOIS response."""
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("whois:"):
            server = line.split(":", 1)[1].strip()
            if server:
                return server
    return None


def whois_lookup(target: str, timeout: float = 10.0) -> Dict[str, object]:
    """Look up WHOIS data, following IANA -> RIR referrals.

    Never raises: any failure is reported in the returned dict.
    """
    try:
        if "." in target and all(p.isdigit() for p in target.split(".")):
            query = target  # IP address
        else:
            query = target.split(".")[-1]  # TLD for a domain
        text = _whois_query("whois.iana.org", query, timeout)
        referral = _find_referral(text)
        servers = ["whois.iana.org"]
        if referral and referral != "whois.iana.org":
            text = _whois_query(referral, target, timeout)
            servers.append(referral)
            second = _find_referral(text)
            if second and second not in servers:
                text = _whois_query(second, target, timeout)
                servers.append(second)
        return {"servers": servers, "text": text, "error": None}
    except (socket.timeout, socket.error, OSError, ValueError) as exc:
        return {"servers": [], "text": "", "error": str(exc)}


def reverse_ip_query_name(ip: str) -> str:
    """Build the reverse-DNS query name for an IPv4 or IPv6 address."""
    if ":" in ip:
        # IPv6: nibble-reversed ip6.arpa name.
        import ipaddress
        addr = ipaddress.IPv6Address(ip)
        nibbles = addr.exploded.replace(":", "")
        return ".".join(reversed(nibbles)) + ".ip6.arpa"
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def asn_lookup(ip: str, resolver: Resolver) -> Optional[Dict[str, object]]:
    """Look up ASN/org via Team Cymru's DNS (origin.asn.cymru.com)."""
    if ":" in ip:
        import ipaddress
        addr = ipaddress.IPv6Address(ip)
        nibbles = addr.exploded.replace(":", "")
        qname = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"
    else:
        qname = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    try:
        records = resolver.query_records(qname, RTYPES["TXT"])
    except DNSError:
        return None
    for record in records:
        values = record["value"]
        if isinstance(values, list) and values:
            fields = [f.strip() for f in values[0].split("|")]
            if len(fields) >= 4:
                return {"asn": fields[0], "prefix": fields[1],
                        "country": fields[2], "registry": fields[3],
                        "allocated": fields[4] if len(fields) > 4 else ""}
    return None


# ---------------------------------------------------------------------------
# Active checks: wildcard detection, subdomain enumeration, AXFR
# ---------------------------------------------------------------------------

def check_wildcard(domain: str, resolver: Resolver) -> bool:
    """Return True if a random non-existent label resolves (wildcard DNS)."""
    random_label = "dnscan-%s" % secrets.token_hex(6)
    try:
        records = resolver.query_records(
            "%s.%s" % (random_label, domain), RTYPES["A"])
        return bool(records)
    except DNSError:
        return False


def enumerate_subdomains(domain: str, resolver: Resolver,
                         wordlist: List[str], threads: int = 10,
                         delay: float = 0.0) -> List[Dict[str, object]]:
    """Brute-force subdomains from a wordlist, concurrently.

    Returns one entry per found label: {"subdomain", "A": [...],
    "AAAA": [...]}. A DNS failure for a single label is skipped silently.
    """
    found: List[Dict[str, object]] = []

    def probe(label: str) -> Optional[Dict[str, object]]:
        name = "%s.%s" % (label, domain)
        try:
            a_records = resolver.query_records(name, RTYPES["A"])
            aaaa_records = resolver.query_records(name, RTYPES["AAAA"])
        except DNSError:
            return None
        if delay:
            time.sleep(delay)
        if not a_records and not aaaa_records:
            return None
        return {
            "subdomain": name,
            "A": [str(r["value"]) for r in a_records],
            "AAAA": [str(r["value"]) for r in aaaa_records],
        }

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(probe, label): label for label in wordlist}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception:
                result = None
            if result:
                found.append(result)
    found.sort(key=lambda item: item["subdomain"])
    return found


def try_axfr(domain: str, resolver: Resolver) -> Dict[str, object]:
    """Attempt a zone transfer against every NS of the domain.

    Returns {"attempted": bool, "servers": {ns: result}}.
    """
    result: Dict[str, object] = {"attempted": True, "servers": {}}
    try:
        ns_records = resolver.query_records(domain, RTYPES["NS"])
    except DNSError as exc:
        result["error"] = str(exc)
        return result
    if not ns_records:
        result["error"] = "no NS records found for %s" % domain
        return result
    for record in ns_records:
        ns_name = str(record["value"]).rstrip(".")
        try:
            ip_records = resolver.query_records(ns_name, RTYPES["A"])
            ip_records += resolver.query_records(ns_name, RTYPES["AAAA"])
        except DNSError:
            ip_records = []
        ips = [str(r["value"]) for r in ip_records]
        if not ips:
            result["servers"][ns_name] = {
                "status": "error",
                "message": "could not resolve nameserver address",
                "records": []}
            continue
        # One AXFR attempt per nameserver (first reachable IP wins).
        for ip in ips:
            attempt = resolver.axfr(ip, domain)
            result["servers"][ns_name] = attempt
            if attempt["status"] == "success":
                break
    return result


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------

#: Record types queried for a domain by default.
DEFAULT_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA",
                        "DNSKEY", "DS"]


def _txt_values(records: List[Dict[str, object]]) -> List[str]:
    """Flatten TXT record values into a list of strings."""
    values = []
    for record in records:
        value = record["value"]
        if isinstance(value, list):
            values.extend(value)
        elif isinstance(value, str):
            values.append(value)
    return values


def run_scan(target: str, kind: str, resolver: Resolver,
             options: argparse.Namespace) -> Dict[str, object]:
    """Run the full scan and return a structured results dict."""
    results: Dict[str, object] = {
        "tool": "dnscan", "version": __version__, "target": target,
        "target_type": kind,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resolvers": resolver.servers,
        "records": {}, "dnssec": {}, "email": {}, "axfr": None,
        "wildcard": None, "subdomains": [], "reverse": {},
        "asn": {}, "whois": None, "errors": [],
    }
    if kind == "ipv4":
        _scan_ip(target, resolver, options, results)
        return results

    # --- Core DNS records -------------------------------------------------
    for rtype in DEFAULT_RECORD_TYPES:
        try:
            records = resolver.query_records(target, RTYPES[rtype])
            results["records"][rtype] = [
                _record_to_json(r) for r in records]
        except DNSError as exc:
            results["errors"].append("query %s failed: %s" % (rtype, exc))
            results["records"][rtype] = []
    if options.srv:
        srv_found: List[Dict[str, object]] = []
        for service in SRV_SERVICES:
            name = "%s.%s" % (service, target)
            try:
                records = resolver.query_records(name, RTYPES["SRV"])
                for record in records:
                    entry = _record_to_json(record)
                    entry["service"] = service
                    srv_found.append(entry)
            except DNSError:
                continue
        results["records"]["SRV"] = srv_found

    # --- DNSSEC presence ---------------------------------------------------
    dnskey = results["records"].get("DNSKEY", [])
    ds = results["records"].get("DS", [])
    rrsig_seen = any(
        r.get("type_name") == "RRSIG"
        for section in (results["records"].values())
        for r in section if isinstance(r, dict))
    results["dnssec"] = {
        "dnskey_present": bool(dnskey),
        "ds_present": bool(ds),
        "rrsig_seen": rrsig_seen,
        "signed": bool(dnskey or ds),
    }

    # --- Email authentication ----------------------------------------------
    txt_records = results["records"].get("TXT", [])
    txt_values = _txt_values(txt_records)
    results["email"]["spf"] = parse_spf(txt_values)
    try:
        dmarc_records = resolver.query_records(
            "_dmarc.%s" % target, RTYPES["TXT"])
        results["email"]["dmarc"] = parse_dmarc(
            _txt_values(dmarc_records))
    except DNSError as exc:
        results["errors"].append("DMARC query failed: %s" % exc)
        results["email"]["dmarc"] = None
    if options.dkim_selector:
        try:
            dkim_records = resolver.query_records(
                "%s._domainkey.%s" % (options.dkim_selector, target),
                RTYPES["TXT"])
            results["email"]["dkim"] = parse_dkim(
                _txt_values(dkim_records))
            results["email"]["dkim_selector"] = options.dkim_selector
        except DNSError as exc:
            results["errors"].append("DKIM query failed: %s" % exc)
            results["email"]["dkim"] = None

    # --- Zone transfer (opt-in, active) ------------------------------------
    if options.axfr:
        results["axfr"] = try_axfr(target, resolver)

    # --- Subdomain enumeration (active) ------------------------------------
    if not options.no_enum:
        results["wildcard"] = check_wildcard(target, resolver)
        wordlist = BUILTIN_WORDLIST
        if options.wordlist:
            try:
                with open(options.wordlist, "r", encoding="utf-8") as handle:
                    wordlist = [line.strip() for line in handle
                                if line.strip() and
                                not line.strip().startswith("#")]
            except OSError as exc:
                results["errors"].append(
                    "could not read wordlist %s: %s" % (options.wordlist, exc))
        results["subdomains"] = enumerate_subdomains(
            target, resolver, wordlist, threads=options.threads,
            delay=options.delay)

    # --- Reverse DNS + ASN for every discovered IP --------------------------
    ips = set()
    for rtype in ("A", "AAAA"):
        for record in results["records"].get(rtype, []):
            ips.add(str(record["value"]))
    for sub in results["subdomains"]:
        ips.update(sub.get("A", []))
        ips.update(sub.get("AAAA", []))
    for ip in sorted(ips):
        try:
            ptr_records = resolver.query_records(
                reverse_ip_query_name(ip), RTYPES["PTR"])
            results["reverse"][ip] = [str(r["value"]) for r in ptr_records]
        except DNSError:
            results["reverse"][ip] = []
        if not options.no_asn:
            asn = asn_lookup(ip, resolver)
            if asn:
                results["asn"][ip] = asn

    # --- WHOIS ---------------------------------------------------------------
    if not options.no_whois:
        results["whois"] = whois_lookup(target)
    return results


def _scan_ip(ip: str, resolver: Resolver, options: argparse.Namespace,
             results: Dict[str, object]) -> None:
    """Scan an IPv4 target: reverse DNS, ASN and WHOIS only."""
    try:
        ptr_records = resolver.query_records(
            reverse_ip_query_name(ip), RTYPES["PTR"])
        results["reverse"][ip] = [str(r["value"]) for r in ptr_records]
    except DNSError as exc:
        results["errors"].append("PTR query failed: %s" % exc)
        results["reverse"][ip] = []
    if not options.no_asn:
        asn = asn_lookup(ip, resolver)
        if asn:
            results["asn"][ip] = asn
    if not options.no_whois:
        results["whois"] = whois_lookup(ip)


def _record_to_json(record: Dict[str, object]) -> Dict[str, object]:
    """Normalize a parsed record for output (JSON-serializable)."""
    return {"name": record["name"], "type": record["type_name"],
            "type_name": record["type_name"], "ttl": record["ttl"],
            "value": record["value"]}


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------

def _fmt_value(value: object) -> str:
    """Render a parsed RDATA value as a readable string."""
    if isinstance(value, dict):
        if "exchange" in value:  # MX
            return "%s (pref %s)" % (value["exchange"], value["preference"])
        if "target" in value:  # SRV
            return "%s:%s (pri %s, w %s)" % (
                value["target"], value["port"], value["priority"],
                value["weight"])
        if "mname" in value:  # SOA
            return ("mname=%s rname=%s serial=%s refresh=%s retry=%s "
                    "expire=%s minimum=%s" % (
                        value["mname"], value["rname"], value["serial"],
                        value["refresh"], value["retry"], value["expire"],
                        value["minimum"]))
        if "tag" in value:  # CAA
            return 'flags=%s tag=%s value="%s"' % (
                value["flags"], value["tag"], value["value"])
        if "digest" in value:  # DS
            return ("key_tag=%s alg=%s digest_type=%s digest=%s" % (
                value["key_tag"], value["algorithm"],
                value["digest_type"], value["digest"]))
        if "key_bytes" in value:  # DNSKEY
            return ("flags=%s proto=%s alg=%s key_len=%s bytes" % (
                value["flags"], value["protocol"], value["algorithm"],
                value["key_bytes"]))
        if "signer" in value:  # RRSIG
            return ("covers=%s alg=%s signer=%s key_tag=%s" % (
                value["type_covered"], value["algorithm"], value["signer"],
                value["key_tag"]))
        return json.dumps(value)
    if isinstance(value, list):  # TXT
        return " ".join('"%s"' % item for item in value)
    return str(value)


def render_text(results: Dict[str, object], colors: Colors) -> str:
    """Render results as human-readable text."""
    out = io.StringIO()
    out.write("%s\n" % colors.bold(
        "dnscan %s  —  %s" % (results["version"], results["target"])))
    out.write("Scanned at %s (UTC) via %s\n\n" % (
        results["timestamp"], ", ".join(results["resolvers"])))

    records = results["records"]
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "DNSKEY",
                  "DS", "SRV"]:
        entries = records.get(rtype, [])
        if not entries:
            continue
        out.write("%s\n" % colors.cyan("== %s records ==" % rtype))
        for entry in entries:
            extra = ""
            if rtype == "SRV" and "service" in entry:
                extra = " [%s]" % entry["service"]
            out.write("  %s  (TTL %s)%s\n" % (
                _fmt_value(entry["value"]), entry["ttl"], extra))
        out.write("\n")

    dnssec = results["dnssec"]
    if dnssec:
        status = colors.green("SIGNED") if dnssec.get("signed") else \
            colors.yellow("NOT SIGNED")
        out.write("%s\n" % colors.cyan("== DNSSEC =="))
        out.write("  Zone appears %s  (DNSKEY: %s, DS: %s, RRSIG seen: %s)\n\n"
                  % (status, dnssec.get("dnskey_present"),
                     dnssec.get("ds_present"), dnssec.get("rrsig_seen")))

    email = results["email"]
    if email:
        out.write("%s\n" % colors.cyan("== Email authentication =="))
        spf = email.get("spf")
        if spf:
            out.write("  SPF: %s  (all: %s, includes: %s)\n" % (
                spf["record"][:80], spf.get("all"),
                ", ".join(spf.get("includes", [])) or "-"))
        else:
            out.write("  SPF: %s\n" % colors.yellow("no SPF record"))
        dmarc = email.get("dmarc")
        if dmarc:
            out.write("  DMARC: policy=%s  (rua: %s)\n" % (
                dmarc.get("policy"), dmarc.get("rua")))
        else:
            out.write("  DMARC: %s\n" % colors.yellow("no DMARC record"))
        dkim = email.get("dkim")
        if dkim:
            out.write("  DKIM (%s): key type %s, %d chars of public key\n"
                      % (email.get("dkim_selector"), dkim.get("key_type"),
                         dkim.get("public_key_length", 0)))
        elif email.get("dkim_selector"):
            out.write("  DKIM (%s): %s\n" % (
                email["dkim_selector"], colors.yellow("no DKIM record")))
        out.write("\n")

    axfr = results.get("axfr")
    if axfr:
        out.write("%s\n" % colors.cyan("== Zone transfer (AXFR) =="))
        for server, attempt in axfr.get("servers", {}).items():
            status = attempt["status"]
            color = colors.green if status == "success" else colors.red
            out.write("  %s: %s — %s\n" % (
                server, color(status), attempt["message"]))
        if axfr.get("error"):
            out.write("  %s\n" % colors.red(axfr["error"]))
        out.write("\n")

    if results.get("wildcard") is True:
        out.write("%s\n\n" % colors.yellow(
            "WARNING: wildcard DNS detected — subdomain results may include "
            "wildcard noise."))
    subs = results.get("subdomains", [])
    if subs:
        out.write("%s (%d found)\n" % (colors.cyan("== Subdomains =="),
                                        len(subs)))
        for sub in subs:
            ips = sub.get("A", []) + sub.get("AAAA", [])
            out.write("  %s  ->  %s\n" % (
                sub["subdomain"], ", ".join(ips)))
        out.write("\n")

    reverse = results.get("reverse", {})
    if any(reverse.values()):
        out.write("%s\n" % colors.cyan("== Reverse DNS =="))
        for ip, names in sorted(reverse.items()):
            out.write("  %s  ->  %s\n" % (ip, ", ".join(names) or "-"))
        out.write("\n")

    asn = results.get("asn", {})
    if asn:
        out.write("%s\n" % colors.cyan("== ASN / organisation =="))
        for ip, info in sorted(asn.items()):
            out.write("  %s  ->  AS%s  %s  %s  (%s)\n" % (
                ip, info["asn"], info["prefix"], info["country"],
                info["registry"]))
        out.write("\n")

    whois = results.get("whois")
    if whois:
        out.write("%s\n" % colors.cyan("== WHOIS =="))
        if whois.get("error"):
            out.write("  %s\n" % colors.red(
                "WHOIS lookup failed: %s" % whois["error"]))
        else:
            out.write("  Queried: %s\n" % ", ".join(whois["servers"]))
            text = whois["text"]
            out.write("  %s\n" % "\n  ".join(
                line for line in text.splitlines()
                if line.strip() and not line.startswith("%")
                and not line.startswith("#"))[:1500])
        out.write("\n")

    errors = results.get("errors", [])
    if errors:
        out.write("%s\n" % colors.yellow("== Warnings / errors =="))
        for error in errors:
            out.write("  - %s\n" % error)
    return out.getvalue()


def render_json(results: Dict[str, object]) -> str:
    """Render results as indented JSON."""
    return json.dumps(results, indent=2, default=str) + "\n"


def render_csv(results: Dict[str, object]) -> str:
    """Render the record/subdomain/ASN findings as flat CSV rows."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["section", "type", "name", "value", "ttl"])
    for rtype, entries in results.get("records", {}).items():
        for entry in entries:
            writer.writerow(["record", rtype, entry["name"],
                             _fmt_value(entry["value"]), entry["ttl"]])
    for sub in results.get("subdomains", []):
        for ip in sub.get("A", []) + sub.get("AAAA", []):
            writer.writerow(["subdomain", "A/AAAA", sub["subdomain"], ip, ""])
    for ip, names in results.get("reverse", {}).items():
        for name in names:
            writer.writerow(["reverse", "PTR", ip, name, ""])
    for ip, info in results.get("asn", {}).items():
        writer.writerow(["asn", "AS" + str(info["asn"]), ip,
                         "%s %s (%s)" % (info["prefix"], info["country"],
                                          info["registry"]), ""])
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="dnscan",
        description="Advanced passive DNS reconnaissance (stdlib only). "
                    "Only scan domains you own or are authorized to test.",
        epilog="Examples:  dnscan example.com  |  "
               "dnscan example.com --json -o report.json  |  "
               "dnscan example.com --axfr --dkim-selector default")
    parser.add_argument("target", nargs="?",
                        help="domain name or IPv4 address to scan")
    parser.add_argument("--version", action="version",
                        version="dnscan %s" % __version__)
    parser.add_argument("--resolver", action="append", default=[],
                        metavar="IP",
                        help="DNS resolver to use (repeatable; default: "
                             "system resolvers, then 1.1.1.1, 8.8.8.8, "
                             "9.9.9.9)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="per-query timeout in seconds (default: 5)")
    parser.add_argument("--retries", type=int, default=2,
                        help="retries per resolver (default: 2)")
    parser.add_argument("--wordlist", metavar="FILE",
                        help="custom subdomain wordlist (one label per line)")
    parser.add_argument("--threads", type=int, default=10,
                        help="concurrent subdomain probes (default: 10)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="delay in seconds between subdomain queries "
                             "(default: 0)")
    parser.add_argument("--dkim-selector", metavar="SELECTOR",
                        help="check DKIM for this selector "
                             "(e.g. default, google, selector1)")
    parser.add_argument("--axfr", action="store_true",
                        help="attempt a zone transfer (ACTIVE check — "
                             "needs authorization on the target)")
    parser.add_argument("--srv", action="store_true",
                        help="also query common SRV service records")
    parser.add_argument("--no-enum", action="store_true",
                        help="skip subdomain enumeration")
    parser.add_argument("--no-whois", action="store_true",
                        help="skip the WHOIS lookup")
    parser.add_argument("--no-asn", action="store_true",
                        help="skip Team Cymru ASN lookups")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colours in text output")
    parser.add_argument("--json", action="store_true",
                        help="output results as JSON")
    parser.add_argument("--csv", action="store_true",
                        help="output results as CSV")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="write output to a file instead of stdout")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point. Returns a process exit code (0, 1 or 2)."""
    parser = build_parser()
    options = parser.parse_args(argv)
    if options.json and options.csv:
        parser.error("--json and --csv are mutually exclusive")
    if not options.target:
        parser.error("a target domain or IPv4 address is required")
    try:
        target, kind = normalize_target(options.target)
    except UsageError as exc:
        parser.error(str(exc))
    if options.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if options.retries < 0:
        parser.error("--retries must be 0 or greater")
    if options.threads < 1:
        parser.error("--threads must be 1 or greater")
    if options.delay < 0:
        parser.error("--delay must be 0 or greater")

    resolver = Resolver(servers=options.resolver or None,
                        timeout=options.timeout, retries=options.retries)
    try:
        results = run_scan(target, kind, resolver, options)
    except DNSError as exc:
        print("dnscan: DNS failure: %s" % exc, file=sys.stderr)
        return 1
    except Exception as exc:  # never leak a traceback for a runtime failure
        print("dnscan: scan failed: %s" % exc, file=sys.stderr)
        return 1

    # A domain scan that collected nothing and hit only transport
    # errors means the scan itself failed (no resolver reachable).
    if kind == "domain":
        any_data = (
            any(results["records"].get(t) for t in DEFAULT_RECORD_TYPES)
            or bool(results["subdomains"])
            or bool((results.get("whois") or {}).get("text")))
        if not any_data and results["errors"]:
            print("dnscan: all DNS queries failed — no resolver reachable "
                  "or no network access; check --resolver and connectivity",
                  file=sys.stderr)
            return 1

    use_color = (not options.no_color and not options.output
                 and sys.stdout.isatty())
    colors = Colors(use_color)
    if options.json:
        output = render_json(results)
    elif options.csv:
        output = render_csv(results)
    else:
        output = render_text(results, colors)

    if options.output:
        try:
            with open(options.output, "w", encoding="utf-8") as handle:
                handle.write(output)
        except OSError as exc:
            print("dnscan: cannot write %s: %s" % (options.output, exc),
                  file=sys.stderr)
            return 1
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
