"""Unit tests for dnscan (stdlib unittest only).

The DNS parser tests use hand-built wire bytes (a real-style response
for example.com), so they verify the parser against known-good bytes
without needing network access.
"""

import contextlib
import io
import json
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dnscan
from dnscan import (
    BUILTIN_WORDLIST, DNSError, Resolver, UsageError, build_query,
    check_wildcard, decode_name, encode_name, normalize_target, parse_dmarc,
    parse_dkim, parse_message, parse_spf, render_csv, render_json,
    render_text, reverse_ip_query_name, asn_lookup, Colors,
)


def _a_response() -> bytes:
    """Hand-built DNS response: example.com A -> 93.184.216.34.

    Header: id 0x1234, flags 0x8180 (QR, RD, RA), QD=1, AN=1.
    Question: example.com, type A, class IN.
    Answer: name pointer to offset 12, A, IN, TTL 3600, 93.184.216.34.
    """
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack(">HH", 1, 1)
    answer = (
        b"\xc0\x0c"                      # pointer to question name
        + struct.pack(">HHIH", 1, 1, 3600, 4)
        + bytes([93, 184, 216, 34])
    )
    return header + question + answer


def _mx_response() -> bytes:
    """Hand-built response: example.com MX 10 mail.example.com."""
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack(">HH", 15, 1)
    exchange = b"\x04mail\x07example\x03com\x00"
    rdata = struct.pack(">H", 10) + exchange
    answer = (
        b"\xc0\x0c"
        + struct.pack(">HHIH", 15, 1, 300, len(rdata))
        + rdata
    )
    return header + question + answer


def _txt_response() -> bytes:
    """Hand-built response: example.com TXT 'v=spf1 -all'."""
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack(">HH", 16, 1)
    text = b"v=spf1 -all"
    rdata = bytes([len(text)]) + text
    answer = (
        b"\xc0\x0c"
        + struct.pack(">HHIH", 16, 1, 300, len(rdata))
        + rdata
    )
    return header + question + answer


def _soa_response() -> bytes:
    """Hand-built response: example.com SOA."""
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack(">HH", 6, 1)
    mname = b"\x03ns1\x07example\x03com\x00"
    rname = b"\x0ahostmaster\x07example\x03com\x00"
    timers = struct.pack(">IIIII", 2026010101, 7200, 3600, 1209600, 3600)
    rdata = mname + rname + timers
    answer = (
        b"\xc0\x0c"
        + struct.pack(">HHIH", 6, 1, 300, len(rdata))
        + rdata
    )
    return header + question + answer


class TestWireFormat(unittest.TestCase):
    def test_encode_decode_name_roundtrip(self):
        for name in ("example.com", "www.example.com", "a.b.c.d.example.org"):
            encoded = encode_name(name)
            decoded, offset = decode_name(encoded, 0)
            self.assertEqual(decoded, name)
            self.assertEqual(offset, len(encoded))

    def test_encode_root(self):
        self.assertEqual(encode_name("."), b"\x00")
        self.assertEqual(encode_name(""), b"\x00")

    def test_decode_compressed_pointer(self):
        message = _a_response()
        # Answer name at offset 12 + 11 (question) + 4 = 27.
        name, next_offset = decode_name(message, 29)
        self.assertEqual(name, "example.com")
        self.assertEqual(next_offset, 31)

    def test_build_query_structure(self):
        query = build_query("example.com", 1, query_id=0xABCD)
        msg_id, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", query[:12])
        self.assertEqual(msg_id, 0xABCD)
        self.assertTrue(flags & 0x0100)  # RD set
        self.assertEqual((qd, an, ns, ar), (1, 0, 0, 0))
        qtype, qclass = struct.unpack(">HH", query[-4:])
        self.assertEqual((qtype, qclass), (1, 1))

    def test_parse_a_response(self):
        response = parse_message(_a_response())
        self.assertEqual(response["id"], 0x1234)
        self.assertEqual(response["rcode"], 0)
        self.assertEqual(response["rcode_name"], "NOERROR")
        self.assertFalse(response["truncated"])
        self.assertEqual(len(response["answers"]), 1)
        answer = response["answers"][0]
        self.assertEqual(answer["name"], "example.com")
        self.assertEqual(answer["type"], 1)
        self.assertEqual(answer["type_name"], "A")
        self.assertEqual(answer["ttl"], 3600)
        self.assertEqual(answer["value"], "93.184.216.34")

    def test_parse_mx_response(self):
        response = parse_message(_mx_response())
        answer = response["answers"][0]
        self.assertEqual(answer["type_name"], "MX")
        self.assertEqual(answer["value"]["preference"], 10)
        self.assertEqual(answer["value"]["exchange"], "mail.example.com")

    def test_parse_txt_response(self):
        response = parse_message(_txt_response())
        answer = response["answers"][0]
        self.assertEqual(answer["type_name"], "TXT")
        self.assertEqual(answer["value"], ["v=spf1 -all"])

    def test_parse_soa_response(self):
        response = parse_message(_soa_response())
        answer = response["answers"][0]
        self.assertEqual(answer["type_name"], "SOA")
        value = answer["value"]
        self.assertEqual(value["mname"], "ns1.example.com")
        self.assertEqual(value["rname"], "hostmaster.example.com")
        self.assertEqual(value["serial"], 2026010101)
        self.assertEqual(value["refresh"], 7200)
        self.assertEqual(value["minimum"], 3600)

    def test_parse_short_message_raises(self):
        with self.assertRaises(ValueError):
            parse_message(b"\x00\x01\x02")

    def test_parse_nxdomain(self):
        header = struct.pack(">HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0)
        question = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        response = parse_message(header + question)
        self.assertEqual(response["rcode"], 3)
        self.assertEqual(response["rcode_name"], "NXDOMAIN")
        self.assertEqual(response["answers"], [])


class FakeSocket:
    """Stand-in for socket.socket returning one canned DNS response."""

    def __init__(self, response: bytes):
        self._response = response

    def settimeout(self, _timeout):
        pass

    def sendto(self, _data, _addr):
        pass

    def recvfrom(self, _size):
        return self._response, ("1.1.1.1", 53)

    def close(self):
        pass


class TestResolver(unittest.TestCase):
    def test_query_uses_canned_response(self):
        canned = _a_response()
        with mock.patch("dnscan.socket.socket",
                        lambda *a, **k: FakeSocket(canned)):
            resolver = Resolver(servers=["1.1.1.1"], timeout=2, retries=0)
            response = resolver.query("example.com", 1)
        self.assertEqual(response["answers"][0]["value"], "93.184.216.34")

    def test_query_records_returns_answers(self):
        canned = _a_response()
        with mock.patch("dnscan.socket.socket",
                        lambda *a, **k: FakeSocket(canned)):
            resolver = Resolver(servers=["1.1.1.1"], timeout=2, retries=0)
            records = resolver.query_records("example.com", 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["value"], "93.184.216.34")

    def test_query_all_servers_fail_raises(self):
        with mock.patch("dnscan.socket.socket",
                        side_effect=OSError("unreachable")):
            resolver = Resolver(servers=["192.0.2.1"], timeout=0.1,
                                retries=0)
            with self.assertRaises(DNSError):
                resolver.query("example.com", 1)


class StubResolver:
    """Minimal resolver stub for offline logic tests."""

    def __init__(self, mapping):
        self.mapping = mapping

    def query_records(self, name, qtype):
        key = (name, qtype)
        if key in self.mapping:
            return self.mapping[key]
        raise DNSError("no stub for %s/%s" % key)


class TestOfflineLogic(unittest.TestCase):
    def test_wildcard_detected(self):
        stub = StubResolver({("dnscan-abcdef.example.com", 1): [
            {"name": "dnscan-abcdef.example.com", "type": 1,
             "type_name": "A", "class": 1, "ttl": 60,
             "value": "93.184.216.34"}]})
        with mock.patch("dnscan.secrets.token_hex", return_value="abcdef"):
            self.assertTrue(check_wildcard("example.com", stub))

    def test_wildcard_absent(self):
        stub = StubResolver({("dnscan-abcdef.example.com", 1): []})
        with mock.patch("dnscan.secrets.token_hex", return_value="abcdef"):
            self.assertFalse(check_wildcard("example.com", stub))

    def test_asn_lookup_parses_cymru_txt(self):
        stub = StubResolver({
            ("8.8.8.8.origin.asn.cymru.com", 16): [
                {"name": "8.8.8.8.origin.asn.cymru.com", "type": 16,
                 "type_name": "TXT", "class": 1, "ttl": 60,
                 "value": ["15169 | 8.8.8.0/24 | US | arin | 2000-03-30"]}]})
        result = asn_lookup("8.8.8.8", stub)
        self.assertEqual(result["asn"], "15169")
        self.assertEqual(result["prefix"], "8.8.8.0/24")
        self.assertEqual(result["country"], "US")
        self.assertEqual(result["registry"], "arin")


class TestTargetValidation(unittest.TestCase):
    def test_valid_domain(self):
        target, kind = normalize_target("Example.COM")
        self.assertEqual((target, kind), ("example.com", "domain"))

    def test_valid_ipv4(self):
        target, kind = normalize_target("8.8.8.8")
        self.assertEqual((target, kind), ("8.8.8.8", "ipv4"))

    def test_idna_domain(self):
        target, kind = normalize_target("münchen.de")
        self.assertEqual(kind, "domain")
        self.assertTrue(target.startswith("xn--"))

    def test_empty_rejected(self):
        with self.assertRaises(UsageError):
            normalize_target("")

    def test_invalid_label_rejected(self):
        with self.assertRaises(UsageError):
            normalize_target("-bad-.example.com")

    def test_invalid_ipv4_rejected(self):
        with self.assertRaises(UsageError):
            normalize_target("999.1.1.1")

    def test_trailing_dot_ok(self):
        target, kind = normalize_target("example.com.")
        self.assertEqual(target, "example.com")


class TestEmailParsing(unittest.TestCase):
    def test_spf_parsing(self):
        result = parse_spf(["v=spf1 include:_spf.google.com ip4:1.2.3.4 -all"])
        self.assertEqual(result["includes"], ["_spf.google.com"])
        self.assertEqual(result["ip4"], ["1.2.3.4"])
        self.assertEqual(result["all"], "-all")

    def test_spf_missing(self):
        self.assertIsNone(parse_spf(["hello world"]))

    def test_dmarc_parsing(self):
        result = parse_dmarc(
            ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"])
        self.assertEqual(result["policy"], "reject")
        self.assertEqual(result["rua"], "mailto:dmarc@example.com")
        self.assertEqual(result["pct"], "100")

    def test_dmarc_missing(self):
        self.assertIsNone(parse_dmarc(["v=spf1 -all"]))

    def test_dkim_parsing(self):
        key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7"
        result = parse_dkim(["v=DKIM1; k=rsa; p=%s" % key])
        self.assertEqual(result["key_type"], "rsa")
        self.assertEqual(result["public_key_length"], len(key))
        self.assertTrue(result["public_key_preview"].startswith("MIGfMA0"))


class TestReverseNames(unittest.TestCase):
    def test_ipv4_reverse(self):
        self.assertEqual(reverse_ip_query_name("8.8.8.8"),
                         "8.8.8.8.in-addr.arpa")

    def test_ipv6_reverse(self):
        name = reverse_ip_query_name("2001:db8::1")
        self.assertTrue(name.endswith(".ip6.arpa"))
        self.assertTrue(name.startswith("1.0.0.0."))


class TestRenderers(unittest.TestCase):
    def _sample_results(self):
        return {
            "tool": "dnscan", "version": "1.0.0", "target": "example.com",
            "target_type": "domain", "timestamp": "2026-01-01T00:00:00+00:00",
            "resolvers": ["1.1.1.1"],
            "records": {"A": [{"name": "example.com", "type": "A",
                               "type_name": "A", "ttl": 3600,
                               "value": "93.184.216.34"}],
                        "TXT": [{"name": "example.com", "type": "TXT",
                                 "type_name": "TXT", "ttl": 300,
                                 "value": ["v=spf1 -all"]}]},
            "dnssec": {"dnskey_present": False, "ds_present": False,
                       "rrsig_seen": False, "signed": False},
            "email": {"spf": {"record": "v=spf1 -all", "includes": [],
                              "ip4": [], "ip6": [], "mechanisms": [],
                              "all": "-all", "redirect": None},
                      "dmarc": None, "dkim": None},
            "axfr": None, "wildcard": False,
            "subdomains": [{"subdomain": "www.example.com",
                            "A": ["93.184.216.34"], "AAAA": []}],
            "reverse": {"93.184.216.34": ["example.com"]},
            "asn": {"93.184.216.34": {"asn": "15133",
                                       "prefix": "93.184.216.0/24",
                                       "country": "US", "registry": "arin",
                                       "allocated": ""}},
            "whois": {"servers": ["whois.iana.org"], "text": "ok",
                      "error": None},
            "errors": [],
        }

    def test_render_json_is_valid(self):
        output = render_json(self._sample_results())
        parsed = json.loads(output)
        self.assertEqual(parsed["target"], "example.com")
        self.assertEqual(parsed["records"]["A"][0]["value"], "93.184.216.34")

    def test_render_csv_has_header_and_rows(self):
        import csv as csv_module
        output = render_csv(self._sample_results())
        rows = list(csv_module.reader(io.StringIO(output)))
        self.assertEqual(rows[0],
                         ["section", "type", "name", "value", "ttl"])
        self.assertTrue(any(row[0] == "record" and row[1] == "A"
                            for row in rows))
        self.assertTrue(any(row[0] == "subdomain" for row in rows))

    def test_render_text_contains_sections(self):
        text = render_text(self._sample_results(), Colors(enabled=False))
        for section in ("A records", "Email authentication", "Subdomains",
                        "Reverse DNS", "ASN / organisation", "WHOIS"):
            self.assertIn(section, text)
        self.assertIn("93.184.216.34", text)
        self.assertIn("no DMARC record", text)


class TestWordlistAndCli(unittest.TestCase):
    def test_wordlist_has_enough_labels(self):
        self.assertGreaterEqual(len(BUILTIN_WORDLIST), 90)
        self.assertEqual(len(set(BUILTIN_WORDLIST)), len(BUILTIN_WORDLIST))
        self.assertIn("www", BUILTIN_WORDLIST)
        self.assertIn("mail", BUILTIN_WORDLIST)
        self.assertIn("api", BUILTIN_WORDLIST)

    def test_help_exits_zero(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                dnscan.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_missing_target_exits_two(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                dnscan.main([])
        self.assertEqual(ctx.exception.code, 2)

    def test_json_and_csv_conflict_exits_two(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                dnscan.main(["example.com", "--json", "--csv"])
        self.assertEqual(ctx.exception.code, 2)

    def test_version_flag(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as ctx:
                dnscan.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("dnscan", out.getvalue())


class TestStdlibOnly(unittest.TestCase):
    def test_no_third_party_imports(self):
        import ast
        tree = ast.parse(Path(dnscan.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        stdlib = getattr(sys, "stdlib_module_names", None)
        if stdlib is None:  # Python < 3.10 fallback
            stdlib = {"argparse", "csv", "io", "json", "random", "re",
                      "secrets", "socket", "struct", "sys", "time",
                      "concurrent", "datetime", "typing", "ipaddress"}
        non_stdlib = imported - set(stdlib) - {"__future__"}
        self.assertEqual(non_stdlib, set(),
                         "non-stdlib imports found: %s" % non_stdlib)


if __name__ == "__main__":
    unittest.main()
