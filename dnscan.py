#!/usr/bin/env python3
"""
dnscan — reconocimiento de IP/dominio, OSINT-first
------------------------------------------------------
Por defecto es 100% pasivo: no toca al target, solo consulta fuentes
de terceros (RDAP, Team Cymru, Shodan InternetDB, GeoIP, crt.sh).
Módulos opcionales (--cve, --vt) siguen siendo pasivos: consultan APIs
externas, nunca al target. --scan-all es ACTIVO: abre conexiones TCP
directas contra el target — úsalo solo con autorización.

Uso:
    python3 dnscan.py 1.1.1.1
    python3 dnscan.py example.com --cve --vt --abuseipdb --format json
    python3 dnscan.py 1.1.1.1 --scan-all --ports 1-1024,8080,8443
    python3 dnscan.py --check-keys

IPs privadas/loopback/reservadas (127.0.0.1, 192.168.x.x, etc.): Shodan
InternetDB y GeoIP se omiten automáticamente — esas fuentes solo indexan
rangos públicos de internet, no tiene sentido consultarlas.

Sin dependencias externas. Solo stdlib.
"""

from __future__ import annotations
import argparse
import concurrent.futures
import ipaddress
import json
import os
import socket
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

__version__ = "2.1.0"

# ─────────────────────────────── config ─────────────────────────────────

TIMEOUT = 6
CYMRU_WHOIS = ("whois.cymru.com", 43)
CIRCL_API = "https://cve.circl.lu/api"
UA = f"dnscan/{__version__} (+osint-only)"

# rango por defecto para --scan-all: well-known + servicios comunes
DEFAULT_SCAN_PORTS = sorted(set(range(1, 1025)) | {
    1433, 1521, 2375, 2376, 3000, 3306, 3389, 5000, 5432, 5601, 5900,
    5984, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9042,
    9090, 9092, 9200, 9300, 11211, 15672, 27017, 27018, 50000,
})

NOCOLOR = not sys.stdout.isatty()


def _c(code: str) -> str:
    return "" if NOCOLOR else code


DIM, CYAN, BOLD, RED, YEL, GRN, RST = (
    _c("\033[2m"), _c("\033[36m"), _c("\033[1m"),
    _c("\033[31m"), _c("\033[33m"), _c("\033[32m"), _c("\033[0m"),
)

BANNER = f"""{CYAN}{BOLD}
     _                          
  __| |_ __  ___  ___ __ _ _ __  
 / _` | '_ \\/ __|/ __/ _` | '_ \\ 
| (_| | | | \\__ \\ (_| (_| | | | |
 \\__,_|_| |_|___/\\___\\__,_|_| |_|
{RST}{DIM} recon osint · v{__version__}{RST}
"""

QUIET = False


def log(msg: str, level: str = "info") -> None:
    if QUIET and level == "info":
        return
    colors = {"info": CYAN, "ok": GRN, "warn": YEL, "err": RED}
    tag = {"info": "*", "ok": "+", "warn": "!", "err": "-"}[level]
    print(f"{colors[level]}[{tag}]{RST} {msg}", file=sys.stderr)


# ─────────────────────────────── http helpers ───────────────────────────

def http_get(url: str, headers: Optional[dict] = None, timeout: int = TIMEOUT,
             quiet_statuses: frozenset = frozenset(), retries: int = 1):
    """GET simple. Devuelve dict/list si es JSON, str si es texto, None si falla.

    quiet_statuses: códigos HTTP que no se loguean como warning (ej. 404 cuando
    significa "sin datos indexados", no un error real).
    retries: reintentos ante timeout/errores transitorios de red (no ante 4xx/5xx).
    """
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    attempt = 0
    while True:
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                if "json" in resp.headers.get("Content-Type", ""):
                    try:
                        return json.loads(raw)
                    except json.JSONDecodeError:
                        return raw
                return raw
        except urllib.error.HTTPError as e:
            if e.code not in quiet_statuses:
                log(f"http fail {url}: {e}", "warn")
            return None
        except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
            if attempt < retries:
                attempt += 1
                time.sleep(0.3)
                continue
            log(f"http fail {url}: {e}", "warn")
            return None


def http_get_status(url: str, headers: Optional[dict] = None, timeout: int = TIMEOUT) -> tuple[int, Any]:
    """Igual que http_get pero devuelve (status_code, body) — usado para validar API keys."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        return -1, str(e)


# ─────────────────────────────── modulos pasivos ────────────────────────

def resolve_target(target: str) -> tuple[str, list[str]]:
    try:
        ipaddress.ip_address(target)
        return "ip", [target]
    except ValueError:
        try:
            infos = socket.getaddrinfo(target, None)
            ips = sorted({i[4][0] for i in infos if ipaddress.ip_address(i[4][0]).version == 4})
            return "domain", ips or []
        except socket.gaierror as e:
            log(f"no se pudo resolver {target}: {e}", "err")
            return "domain", []


def ip_scope(ip: str) -> str:
    """Clasifica la IP: fuentes OSINT (Shodan/GeoIP) solo indexan direcciones públicas."""
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        return "private"
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    return "public"


def mod_rdap(ip: str) -> dict:
    data = http_get(f"https://rdap.org/ip/{ip}", quiet_statuses=frozenset({404}))
    if not isinstance(data, dict):
        return {}
    out = {
        "handle": data.get("handle"), "name": data.get("name"),
        "country": data.get("country"),
        "start_address": data.get("startAddress"), "end_address": data.get("endAddress"),
    }
    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        vcard = ent.get("vcardArray")
        if vcard and len(vcard) > 1 and ("abuse" in roles or "registrant" in roles):
            fields = {v[0]: v[3] for v in vcard[1] if len(v) >= 4}
            out.setdefault("contacts", []).append({"roles": roles, **fields})
    return out


def mod_asn_cymru(ip: str) -> dict:
    query = f" -v {ip}\n"
    try:
        with socket.create_connection(CYMRU_WHOIS, timeout=TIMEOUT) as s:
            s.sendall(query.encode())
            resp = b""
            while chunk := s.recv(4096):
                resp += chunk
        lines = resp.decode(errors="replace").strip().splitlines()
        if len(lines) < 2:
            return {}
        header = [h.strip() for h in lines[0].split("|")]
        values = [v.strip() for v in lines[1].split("|")]
        return dict(zip(header, values))
    except OSError as e:
        log(f"cymru whois fail: {e}", "warn")
        return {}


def mod_shodan_internetdb(ip: str) -> dict:
    data = http_get(f"https://internetdb.shodan.io/{ip}", quiet_statuses=frozenset({404}))
    return data if isinstance(data, dict) else {}


def mod_geoip(ip: str) -> dict:
    data = http_get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting")
    if not isinstance(data, dict) or data.get("status") != "success":
        return {}
    return data


def mod_ptr(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def mod_crtsh(domain: str) -> list[str]:
    data = http_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
    if not isinstance(data, list):
        return []
    names = set()
    for entry in data:
        for n in entry.get("name_value", "").split("\n"):
            n = n.strip().lstrip("*.")
            if n and domain in n:
                names.add(n)
    return sorted(names)


# ─────────────────────────────── modulo CVE (pasivo) ────────────────────

def _parse_cpe(cpe: str) -> Optional[tuple[str, str]]:
    parts = cpe.split(":")
    if len(parts) > 4 and parts[0] == "cpe":
        return parts[3], parts[4]  # vendor, product
    return None


def circl_cve(cve_id: str) -> dict:
    data = http_get(f"{CIRCL_API}/cve/{cve_id}", quiet_statuses=frozenset({404}))
    if not isinstance(data, dict) or not data:
        return {"id": cve_id, "found": False}
    return {
        "id": data.get("id", cve_id),
        "cvss": data.get("cvss"),
        "summary": (data.get("summary") or "")[:220],
        "found": True,
        "source": "circl",
    }


def nvd_cve(cve_id: str) -> dict:
    """Fallback a NVD oficial cuando CIRCL no tiene el CVE indexado."""
    data = http_get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", timeout=8)
    if not isinstance(data, dict):
        return {"id": cve_id, "found": False}
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"id": cve_id, "found": False}
    cve = vulns[0].get("cve", {})
    metrics = cve.get("metrics", {})
    cvss = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
            break
    summary = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            summary = (d.get("value") or "")[:220]
            break
    return {"id": cve_id, "cvss": cvss, "summary": summary, "found": True, "source": "nvd"}


def cve_lookup(cve_id: str) -> dict:
    """CIRCL primero, NVD como fallback si no aparece."""
    result = circl_cve(cve_id)
    if not result.get("found"):
        result = nvd_cve(cve_id)
    return result


def circl_search(vendor: str, product: str, cap: int = 5) -> list[dict]:
    data = http_get(f"{CIRCL_API}/search/{vendor}/{product}")
    results = data.get("data") if isinstance(data, dict) else data
    if not isinstance(results, list):
        return []
    out = []
    for entry in results[:cap]:
        out.append({
            "id": entry.get("id"), "cvss": entry.get("cvss"),
            "summary": (entry.get("summary") or "")[:180],
        })
    return out


def mod_cve(shodan_data: dict) -> dict:
    out: dict[str, Any] = {"known_vulns": [], "by_product": {}}
    vulns = shodan_data.get("vulns", [])[:15]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futs = {pool.submit(cve_lookup, v): v for v in vulns}
        for fut in concurrent.futures.as_completed(futs):
            out["known_vulns"].append(fut.result())
    out["known_vulns"].sort(key=lambda v: v["id"])

    products = set()
    for cpe in shodan_data.get("cpes", []):
        parsed = _parse_cpe(cpe)
        if parsed:
            products.add(parsed)
    for vendor, product in list(products)[:5]:
        found = circl_search(vendor, product)
        if found:
            out["by_product"][f"{vendor}/{product}"] = found
    return out


# ─────────────────────────────── modulo VirusTotal (pasivo) ─────────────

def mod_virustotal(target: str, kind: str, api_key: str) -> dict:
    path = "ip_addresses" if kind == "ip" else "domains"
    data = http_get(
        f"https://www.virustotal.com/api/v3/{path}/{target}",
        headers={"x-apikey": api_key},
    )
    if not isinstance(data, dict):
        return {}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation"),
        "categories": attrs.get("categories", {}),
        "as_owner": attrs.get("as_owner"),
    }


# ─────────────────────────────── modulo AbuseIPDB (pasivo) ──────────────

def mod_abuseipdb(ip: str, api_key: str) -> dict:
    data = http_get(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        headers={"Key": api_key, "Accept": "application/json"},
    )
    if not isinstance(data, dict):
        return {}
    d = data.get("data", {})
    return {
        "abuse_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "is_tor": d.get("isTor"),
        "last_reported": d.get("lastReportedAt"),
    }


# ─────────────────────────────── modulo scan activo ─────────────────────

def parse_port_range(spec: str) -> list[int]:
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p <= 65535)


def scan_port(ip: str, port: int, timeout: float) -> Optional[dict]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) != 0:
            return None
        banner = None
        try:
            s.settimeout(0.4)
            data = s.recv(128)
            banner = data.decode(errors="replace").strip() or None
        except OSError:
            pass
        return {"port": port, "state": "open", "banner": banner}
    except OSError:
        return None
    finally:
        s.close()


def mod_scan_all(ip: str, ports: list[int], timeout: float, workers: int) -> list[dict]:
    log(f"scan activo: {len(ports)} puertos, {workers} workers — contacto directo al target", "warn")
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(scan_port, ip, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            if r:
                found.append(r)
    return sorted(found, key=lambda x: x["port"])


# ─────────────────────────────── validacion de API keys ─────────────────

def check_key_vt(key: str) -> tuple[str, str]:
    status, _ = http_get_status("https://www.virustotal.com/api/v3/users/me", {"x-apikey": key})
    if status == 200:
        return "OK", "válida"
    if status in (401, 403):
        return "NOT OK", "inválida o expirada"
    return "UNKNOWN", f"http {status}"


def check_key_abuseipdb(key: str) -> tuple[str, str]:
    status, _ = http_get_status(
        "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1",
        {"Key": key, "Accept": "application/json"},
    )
    if status == 200:
        return "OK", "válida"
    if status in (401, 403):
        return "NOT OK", "inválida o expirada"
    if status == 429:
        return "OK", "válida (rate-limited)"
    return "UNKNOWN", f"http {status}"


def check_key_shodan(key: str) -> tuple[str, str]:
    status, body = http_get_status(f"https://api.shodan.io/api-info?key={key}")
    if status == 200:
        return "OK", "válida"
    if status in (401, 403):
        return "NOT OK", "inválida o expirada"
    return "UNKNOWN", f"http {status}"


def mask(key: str) -> str:
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}...{key[-4:]}"


def mod_check_keys(keys: dict[str, Optional[str]]) -> dict:
    checkers = {"virustotal": check_key_vt, "abuseipdb": check_key_abuseipdb, "shodan": check_key_shodan}
    out = {}
    for name, key in keys.items():
        if not key:
            out[name] = {"configured": False, "status": "NO CONFIGURADA", "detail": "-", "masked": "-"}
            continue
        status, detail = checkers[name](key)
        out[name] = {"configured": True, "status": status, "detail": detail, "masked": mask(key)}
    return out


# ─────────────────────────────── report model ────────────────────────────

@dataclass
class Report:
    target: str = ""
    resolved_ips: list[str] = field(default_factory=list)
    ip_scope: str = "public"
    rdap: dict = field(default_factory=dict)
    asn: dict = field(default_factory=dict)
    shodan: dict = field(default_factory=dict)
    geoip: dict = field(default_factory=dict)
    ptr: dict = field(default_factory=dict)
    cert_subdomains: list = field(default_factory=list)
    cve: dict = field(default_factory=dict)
    virustotal: dict = field(default_factory=dict)
    abuseipdb: dict = field(default_factory=dict)
    active_ports: list = field(default_factory=list)
    keys_status: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    elapsed_s: float = 0.0


# ─────────────────────────────── orquestador ─────────────────────────────

def run(target: str, args: argparse.Namespace, keys: dict[str, Optional[str]]) -> Report:
    t0 = time.time()
    r = Report(target=target)

    kind, ips = resolve_target(target)
    if not ips:
        r.errors.append("resolución fallida — sin IPs para analizar")
        r.elapsed_s = time.time() - t0
        return r
    r.resolved_ips = ips
    ip = ips[0]
    r.ip_scope = ip_scope(ip)

    jobs: dict[str, tuple] = {
        "rdap": (mod_rdap, ip),
        "asn": (mod_asn_cymru, ip),
    }
    if r.ip_scope == "public":
        jobs["shodan"] = (mod_shodan_internetdb, ip)
        jobs["geoip"] = (mod_geoip, ip)
    else:
        r.notes.append(
            f"IP {ip} es {r.ip_scope} — Shodan InternetDB y GeoIP se omiten "
            "(solo indexan rangos públicos de internet)"
        )
    if not args.stealth:
        jobs["ptr"] = (mod_ptr, ip)
    if kind == "domain":
        jobs["crtsh"] = (mod_crtsh, target)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futs = {}
        for name, (fn, *fargs) in jobs.items():
            futs[pool.submit(fn, *fargs)] = name
            time.sleep(0.12)
        for fut in concurrent.futures.as_completed(futs):
            name = futs[fut]
            try:
                res = fut.result()
            except Exception as e:  # noqa: BLE001
                r.errors.append(f"{name}: {e}")
                continue
            if name == "rdap":
                r.rdap = res or {}
            elif name == "asn":
                r.asn = res or {}
            elif name == "shodan":
                r.shodan = res or {}
            elif name == "geoip":
                r.geoip = res or {}
            elif name == "ptr":
                r.ptr = {ip: res} if res else {}
            elif name == "crtsh":
                r.cert_subdomains = res or []

    if args.cve:
        if not r.shodan.get("vulns") and not r.shodan.get("cpes"):
            r.notes.append("--cve: sin CPEs/vulns de Shodan para correlacionar (nada que buscar)")
        else:
            log("consultando CVE (cve-search / CIRCL, fallback NVD)...", "info")
            r.cve = mod_cve(r.shodan)

    if args.vt:
        if not keys.get("virustotal"):
            r.errors.append("--vt requiere VT_API_KEY (env) o --vt-key")
        else:
            log("consultando VirusTotal...", "info")
            r.virustotal = mod_virustotal(target if kind == "domain" else ip, kind, keys["virustotal"])

    if args.abuseipdb:
        if not keys.get("abuseipdb"):
            r.errors.append("--abuseipdb requiere ABUSEIPDB_API_KEY (env) o --abuseipdb-key")
        elif r.ip_scope != "public":
            r.notes.append(f"--abuseipdb: IP {ip} es {r.ip_scope}, no aplica")
        else:
            log("consultando AbuseIPDB...", "info")
            r.abuseipdb = mod_abuseipdb(ip, keys["abuseipdb"])

    if args.scan_all:
        ports = parse_port_range(args.ports) if args.ports else DEFAULT_SCAN_PORTS
        r.active_ports = mod_scan_all(ip, ports, args.scan_timeout, args.workers)

    r.elapsed_s = round(time.time() - t0, 2)
    return r


# ─────────────────────────────── formatters ──────────────────────────────

def sev_color(cvss: Optional[float]) -> str:
    if cvss is None:
        return DIM
    if cvss >= 9:
        return RED + BOLD
    if cvss >= 7:
        return RED
    if cvss >= 4:
        return YEL
    return GRN


def fmt_table(r: Report, args: argparse.Namespace) -> str:
    out = []
    out.append(f"{BOLD}── {r.target} ──{RST}  {DIM}{r.elapsed_s}s{RST}")
    scope_col = GRN if r.ip_scope == "public" else DIM
    out.append(f"IPs: {', '.join(r.resolved_ips) or '—'}   {scope_col}[{r.ip_scope}]{RST}")

    if r.rdap:
        out.append(f"\n{CYAN}RDAP{RST}")
        out.append(f"  org     : {r.rdap.get('name') or r.rdap.get('handle') or '—'}")
        out.append(f"  país    : {r.rdap.get('country') or '—'}")
        out.append(f"  rango   : {r.rdap.get('start_address','—')} - {r.rdap.get('end_address','—')}")

    if r.asn:
        out.append(f"\n{CYAN}ASN / BGP{RST}")
        for k in ("AS", "AS Name", "BGP Prefix", "CC", "Registry"):
            if k in r.asn:
                out.append(f"  {k:10}: {r.asn[k]}")

    if r.geoip:
        out.append(f"\n{CYAN}GeoIP{RST}")
        out.append(f"  isp/org : {r.geoip.get('isp')} / {r.geoip.get('org')}")
        out.append(f"  ubicac. : {r.geoip.get('city')}, {r.geoip.get('regionName')}, {r.geoip.get('country')}")
        out.append(f"  flags   : hosting={r.geoip.get('hosting')} proxy={r.geoip.get('proxy')}")

    if r.shodan:
        out.append(f"\n{CYAN}Shodan InternetDB (pasivo){RST}")
        out.append(f"  puertos : {', '.join(map(str, r.shodan.get('ports', []))) or '—'}")
        hn = r.shodan.get("hostnames", [])
        if hn:
            out.append(f"  hosts   : {', '.join(hn)}")
        vulns = r.shodan.get("vulns", [])
        if vulns:
            out.append(f"  {RED}vulns   : {', '.join(vulns[:12])}{'...' if len(vulns) > 12 else ''}{RST}")

    if r.ptr:
        out.append(f"\n{CYAN}Reverse DNS{RST}")
        for ip, name in r.ptr.items():
            out.append(f"  {ip} -> {name}")

    if r.cert_subdomains:
        out.append(f"\n{CYAN}Subdominios (crt.sh) — {len(r.cert_subdomains)}{RST}")
        for s in r.cert_subdomains[:15]:
            out.append(f"  {s}")
        if len(r.cert_subdomains) > 15:
            out.append(f"  {DIM}... +{len(r.cert_subdomains)-15} más{RST}")

    if r.cve:
        known = r.cve.get("known_vulns", [])
        by_prod = r.cve.get("by_product", {})
        out.append(f"\n{CYAN}CVE (cve-search / CIRCL, fallback NVD){RST}")
        if not known and not by_prod:
            out.append(f"  {DIM}sin resultados{RST}")
        for v in known:
            col = sev_color(v.get("cvss"))
            src = f" {DIM}[{v.get('source','?')}]{RST}" if v.get("found") else f" {DIM}[no encontrado]{RST}"
            out.append(f"  {col}{v['id']:16} cvss={v.get('cvss','—')}{RST}{src}  {v.get('summary','')[:80]}")
        for prod, items in by_prod.items():
            out.append(f"  {DIM}{prod}:{RST}")
            for it in items:
                col = sev_color(it.get("cvss"))
                out.append(f"    {col}{it['id']:16} cvss={it.get('cvss','—')}{RST}")

    if r.virustotal:
        v = r.virustotal
        mal = v.get("malicious", 0)
        col = RED if mal > 0 else GRN
        out.append(f"\n{CYAN}VirusTotal{RST}")
        out.append(f"  {col}malicious={mal} suspicious={v.get('suspicious',0)}{RST} "
                    f"harmless={v.get('harmless',0)} undetected={v.get('undetected',0)}")
        out.append(f"  reputation={v.get('reputation')}  as_owner={v.get('as_owner')}")

    if r.abuseipdb:
        a = r.abuseipdb
        score = a.get("abuse_score", 0) or 0
        col = RED if score > 50 else YEL if score > 0 else GRN
        out.append(f"\n{CYAN}AbuseIPDB{RST}")
        out.append(f"  {col}score={score}/100{RST}  reports={a.get('total_reports')}  tor={a.get('is_tor')}")
        out.append(f"  isp={a.get('isp')}  último reporte={a.get('last_reported') or '—'}")

    if r.active_ports:
        out.append(f"\n{YEL}Scan activo — puertos abiertos ({len(r.active_ports)}){RST}")
        for p in r.active_ports:
            b = f"  {DIM}{p['banner'][:60]}{RST}" if p.get("banner") else ""
            out.append(f"  {p['port']:>5}/tcp open{b}")
    elif args.scan_all:
        out.append(f"\n{YEL}Scan activo{RST}\n  sin puertos abiertos detectados")

    if r.keys_status:
        out.append(f"\n{CYAN}Estado de API keys{RST}")
        for name, s in r.keys_status.items():
            col = GRN if s["status"] == "OK" else RED if s["status"] == "NOT OK" else DIM
            out.append(f"  {name:12}: {col}{s['status']:15}{RST} {s['masked']:14} {DIM}{s['detail']}{RST}")

    if r.notes:
        out.append(f"\n{DIM}Notas{RST}")
        for n in r.notes:
            out.append(f"  {DIM}- {n}{RST}")

    if r.errors:
        out.append(f"\n{YEL}Avisos{RST}")
        for e in r.errors:
            out.append(f"  - {e}")

    return "\n".join(out)


def fmt_json(r: Report) -> str:
    return json.dumps(asdict(r), indent=2, ensure_ascii=False)


def fmt_markdown(r: Report) -> str:
    d = asdict(r)
    lines = [
        f"# recon: {r.target}", "",
        f"`{r.elapsed_s}s` · IPs: {', '.join(r.resolved_ips) or '—'} · scope: `{r.ip_scope}`", "",
    ]
    skip = {"target", "resolved_ips", "elapsed_s", "ip_scope"}
    for section, content in d.items():
        if section in skip or not content:
            continue
        lines.append(f"## {section}")
        lines.append("```json")
        lines.append(json.dumps(content, indent=2, ensure_ascii=False))
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


FORMATTERS = {"table": fmt_table, "json": lambda r, a: fmt_json(r), "markdown": lambda r, a: fmt_markdown(r)}


# ─────────────────────────────── cli ─────────────────────────────────────

class SpacedHelpAction(argparse.Action):
    """Igual que -h/--help pero con una línea en blanco antes y después."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        print()
        parser.print_help()
        print()
        parser.exit()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dnscan",
        description="Recon de IP/dominio — OSINT pasivo por defecto, módulos activos opcionales.",
        epilog=(
            "ejemplos:\n"
            "  dnscan 1.1.1.1\n"
            "  dnscan example.com --cve --vt --abuseipdb\n"
            "  dnscan example.com --format json --output out.json\n"
            "  dnscan 1.1.1.1 --scan-all --ports 1-1024,8080,8443\n"
            "  dnscan --check-keys\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    p.add_argument("-h", "--help", action=SpacedHelpAction, help="show this help message and exit")
    p.add_argument("target", nargs="?", help="IP o dominio")

    g_out = p.add_argument_group("salida")
    g_out.add_argument("--format", choices=["table", "json", "markdown"], default="table", help="formato de salida (default: table)")
    g_out.add_argument("--json", action="store_true", help="atajo de --format json")
    g_out.add_argument("--output", metavar="FILE", help="guardar salida en archivo")
    g_out.add_argument("--no-color", action="store_true", help="desactiva colores ANSI")
    g_out.add_argument("--no-banner", action="store_true", help="omite el banner")
    g_out.add_argument("-q", "--quiet", action="store_true", help="solo el reporte final, sin logs")

    g_pas = p.add_argument_group("pasivo")
    g_pas.add_argument("--stealth", action="store_true", help="omite incluso PTR reverse DNS")
    g_pas.add_argument("--quick", action="store_true", help="solo RDAP+ASN+GeoIP (más rápido)")

    g_ext = p.add_argument_group("enriquecimiento (pasivo, requiere red)")
    g_ext.add_argument("--cve", action="store_true", help="correlaciona CVEs conocidos vía cve-search (CIRCL) usando CPEs/vulns de Shodan InternetDB")
    g_ext.add_argument("--vt", action="store_true", help="consulta reputación en VirusTotal (requiere VT_API_KEY o --vt-key)")
    g_ext.add_argument("--vt-key", metavar="KEY", help="API key de VirusTotal (o export VT_API_KEY)")
    g_ext.add_argument("--abuseipdb", action="store_true", help="consulta reputación en AbuseIPDB (requiere ABUSEIPDB_API_KEY o --abuseipdb-key)")
    g_ext.add_argument("--abuseipdb-key", metavar="KEY", help="API key de AbuseIPDB (o export ABUSEIPDB_API_KEY)")
    g_ext.add_argument("--shodan-key", metavar="KEY", help="API key de Shodan, solo para --check-keys (o export SHODAN_API_KEY)")
    g_ext.add_argument("--timeout", type=int, default=TIMEOUT, help=f"timeout de red en segundos para módulos pasivos (default: {TIMEOUT})")

    g_act = p.add_argument_group("activo — contacta directamente al target")
    g_act.add_argument("--scan-all", action="store_true", help="TCP connect scan de puertos abiertos (ACTIVO)")
    g_act.add_argument("--ports", metavar="RANGE", help="rango custom, ej: 1-1024,8080,8443 (default: top well-known + comunes)")
    g_act.add_argument("--workers", type=int, default=200, help="concurrencia del scan (default: 200)")
    g_act.add_argument("--scan-timeout", type=float, default=0.8, help="timeout por puerto en segundos (default: 0.8)")

    g_keys = p.add_argument_group("utilidades")
    g_keys.add_argument("--check-keys", action="store_true", help="valida las API keys configuradas (VT/AbuseIPDB/Shodan) y sale")
    g_keys.add_argument("--full", action="store_true", help="atajo: --cve --vt (sin scan-all, sin sorpresas activas)")
    p.add_argument("-V", "--version", action="version", version=f"dnscan {__version__}")
    return p


def load_keys(args: argparse.Namespace) -> dict[str, Optional[str]]:
    return {
        "virustotal": args.vt_key or os.environ.get("VT_API_KEY"),
        "abuseipdb": args.abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY"),
        "shodan": args.shodan_key or os.environ.get("SHODAN_API_KEY"),
    }


def main() -> None:
    global NOCOLOR, DIM, CYAN, BOLD, RED, YEL, GRN, RST, QUIET, TIMEOUT

    parser = build_parser()
    args = parser.parse_args()

    if args.no_color:
        NOCOLOR = True
        DIM = CYAN = BOLD = RED = YEL = GRN = RST = ""
    if args.json:
        args.format = "json"
    if args.full:
        args.cve = True
        args.vt = True
    TIMEOUT = args.timeout
    QUIET = args.quiet or args.format != "table"

    keys = load_keys(args)
    print()  # espacio inicial

    try:
        if args.check_keys:
            if not args.no_banner and args.format == "table":
                print(BANNER, file=sys.stderr)
            status = mod_check_keys(keys)
            if args.format == "json":
                print(json.dumps(status, indent=2, ensure_ascii=False))
            else:
                print(f"{BOLD}── estado de API keys ──{RST}")
                for name, s in status.items():
                    col = GRN if s["status"] == "OK" else RED if s["status"] == "NOT OK" else DIM
                    print(f"  {name:12}: {col}{s['status']:15}{RST} {s['masked']:14} {DIM}{s['detail']}{RST}")
            return

        if not args.target:
            parser.error("target requerido (o usa --check-keys)")

        if args.quick:
            args.stealth = True

        if not args.no_banner and args.format == "table":
            print(BANNER, file=sys.stderr)

        log(f"iniciando recon sobre {args.target}", "info")
        if args.scan_all:
            log("modo activo habilitado — se abrirán conexiones TCP directas al target", "warn")

        r = run(args.target, args, keys)
        rendered = FORMATTERS[args.format](r, args)

        if args.output:
            with open(args.output, "w") as f:
                f.write(rendered if args.format != "table" else _strip_ansi(rendered))
            log(f"guardado en {args.output}", "ok")
        else:
            print(rendered)
    finally:
        print()  # espacio final


def _strip_ansi(s: str) -> str:
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)


if __name__ == "__main__":
    main()
