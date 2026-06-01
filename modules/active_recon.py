"""
Active Reconnaissance Module – CYS-ILM v3.0
Performs direct interaction with the target: port scanning, banner grabbing,
technology fingerprinting, header analysis, and basic vulnerability checks.

SYN-scan modes (standard / comprehensive / stealth) require root.
The main entry point handles privilege escalation automatically.
"""

import concurrent.futures
import ipaddress
import logging
import os
import re
import socket
import ssl
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import nmap
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Conservative request defaults (no version leakage in UA)
_UA      = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
_TIMEOUT = 6   # seconds

# Ports classified as high-risk when open
_HIGH_RISK_PORTS = {21, 23, 25, 110, 111, 135, 137, 139, 161, 389, 512, 513,
                    514, 515, 873, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
                    6379, 27017}


class ActiveReconnaissance:
    """Active discovery: ports, banners, technologies, headers, vulns."""

    def __init__(self, verbose: bool = False) -> None:
        if verbose:
            logger.setLevel(logging.DEBUG)

        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError as exc:
            logger.error(f"nmap init failed: {exc}")
            raise

        self.timeout     = 4
        self.max_threads = 25

    # ── Port scan ────────────────────────────────────────────────
    def comprehensive_port_scan(self, target: str, **kw) -> Dict[str, Any]:
        ports     = kw.get("ports",           "1-1000")
        scan_type = kw.get("scan_type",       "quick")
        timing    = kw.get("timing_template", 3)
        privileged = os.geteuid() == 0

        logger.info(f"Port scan [{scan_type}]  target={target}  "
                    f"ports={ports}  privileged={privileged}")

        result: Dict[str, Any] = {
            "target":        target,
            "scan_type":     scan_type,
            "ports_scanned": ports,
            "open_ports":    [],
            "scan_stats":    {"status": "pending"},
            "start_time":    datetime.now().isoformat(),
        }

        try:
            args = self._nmap_args(scan_type, timing, privileged)
            logger.debug(f"nmap args: {args}")

            try:
                self.nm.scan(target, ports, arguments=args, timeout=360)
            except nmap.PortScannerError as exc:
                msg = str(exc).lower()
                if "root" in msg or "privilege" in msg or "permission" in msg:
                    # Graceful fallback to TCP-connect (no root needed)
                    logger.warning("Falling back to TCP-connect scan (no root)")
                    args = self._nmap_args("tcp_connect", timing, privileged=False)
                    self.nm.scan(target, ports, arguments=args, timeout=360)
                else:
                    raise

            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port, info in self.nm[host][proto].items():
                        if info["state"] == "open":
                            result["open_ports"].append({
                                "port":      port,
                                "protocol":  proto,
                                "state":     "open",
                                "service":   info.get("name",    "unknown"),
                                "product":   info.get("product", ""),
                                "version":   info.get("version", ""),
                                "extrainfo": info.get("extrainfo",""),
                                "cpe":       info.get("cpe",     ""),
                                "risk":      port in _HIGH_RISK_PORTS,
                            })
                            logger.info(f"  OPEN  {port}/{proto}  "
                                        f"{info.get('name','?')} "
                                        f"{info.get('product','')} "
                                        f"{info.get('version','')}")

            result["scan_stats"] = {
                "open_count": len(result["open_ports"]),
                "status":     "completed",
            }

        except Exception as exc:
            logger.error(f"Port scan error: {exc}")
            result["error"]                 = str(exc)
            result["scan_stats"]["status"]  = "failed"

        result["end_time"] = datetime.now().isoformat()
        return result

    def _nmap_args(self, scan_type: str, timing: int, privileged: bool) -> str:
        _map = {
            "quick":         f"-T{timing} -F  --max-retries 1 --min-rate 100",
            "standard":      f"-T{timing} -sS --max-retries 2 --min-rate 50",
            "comprehensive": f"-T{timing} -sS -sV -sC --max-retries 2 --min-rate 20",
            "stealth":       f"-T{timing} -sS -f --mtu 24 --max-retries 1",
            "tcp_connect":   f"-T{timing} -sT --max-retries 1 --min-rate 50",
        }
        if not privileged and scan_type in ("standard","comprehensive","stealth"):
            scan_type = "tcp_connect"

        args = _map.get(scan_type, _map["quick"])
        args += " -Pn --open"      # treat host as up; show only open ports
        return args

    # ── Banner grabbing ──────────────────────────────────────────
    def banner_grabbing(self, target: str,
                        ports: Optional[List[int]] = None) -> Dict[int, Dict]:
        if ports is None:
            ports = [21,22,23,25,53,80,110,143,443,445,
                     993,995,1433,3306,3389,5900,8080,8443]
        logger.info(f"Banner grab  target={target}  ports={len(ports)}")
        results: Dict[int, Dict] = {}

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(len(ports), self.max_threads)) as ex:
            future_map = {ex.submit(self._grab, target, p): p for p in ports}
            for fut in concurrent.futures.as_completed(future_map):
                p = future_map[fut]
                try:
                    info = fut.result(timeout=self.timeout + 2)
                    if info:
                        results[p] = info
                        logger.debug(f"Banner {p}: {str(info.get('banner',''))[:60]}")
                except Exception:
                    pass

        logger.info(f"Banners grabbed: {len(results)}/{len(ports)}")
        return results

    def _grab(self, target: str, port: int) -> Optional[Dict]:
        try:
            with socket.create_connection((target, port),
                                          timeout=self.timeout) as s:
                s.settimeout(1.5)
                banner = b""
                try:
                    banner = s.recv(1024)
                except socket.timeout:
                    pass

                extra: Dict[str, str] = {}
                if port in (80, 8080):
                    try:
                        s.send(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
                        extra["http"] = s.recv(2048).decode("utf-8","ignore")[:400]
                    except Exception:
                        pass
                elif port == 21:
                    try:
                        s.send(b"SYST\r\n")
                        extra["ftp"] = s.recv(512).decode("utf-8","ignore")
                    except Exception:
                        pass

                if banner or extra:
                    return {
                        "port":    port,
                        "banner":  banner.decode("utf-8","ignore").strip(),
                        "extra":   extra,
                    }
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        except Exception as exc:
            logger.debug(f"Banner {port}: {exc}")
        return None

    # ── Technology fingerprinting ────────────────────────────────
    def technology_detection(self, target: str,
                             ports: Optional[List[int]] = None) -> Dict[str, List[str]]:
        if ports is None:
            ports = [80, 443, 8080, 8443]
        logger.info(f"Tech detection  target={target}")

        cats: Dict[str, List[str]] = {
            "web_server": [], "programming_language": [], "framework": [],
            "javascript": [], "cms": [], "analytics": [], "cdn": [],
            "security": [], "misc": [],
        }

        for port in ports:
            for scheme in ("https", "http"):
                url = f"{scheme}://{target}" + (f":{port}" if port not in (80,443) else "")
                try:
                    r = requests.get(
                        url, headers={"User-Agent": _UA},
                        timeout=_TIMEOUT, verify=False,
                        allow_redirects=True, stream=False,
                    )
                    self._parse_headers(r.headers, cats)
                    ct = r.headers.get("Content-Type","")
                    if "text/html" in ct:
                        self._parse_html(r.text, cats)
                    break
                except requests.RequestException:
                    continue

        # Deduplicate
        return {k: list(dict.fromkeys(v)) for k, v in cats.items() if v}

    def _parse_headers(self, hdrs: Any, cats: Dict) -> None:
        _map = {
            "Server": {
                "apache": ("web_server","Apache"),
                "nginx":  ("web_server","Nginx"),
                "iis":    ("web_server","Microsoft IIS"),
                "caddy":  ("web_server","Caddy"),
                "gunicorn":("web_server","Gunicorn"),
                "lighttpd":("web_server","LightTPD"),
            },
            "X-Powered-By": {
                "php":    ("programming_language","PHP"),
                "asp.net":("framework","ASP.NET"),
                "express":("framework","Express.js"),
                "django": ("framework","Django"),
                "rails":  ("framework","Ruby on Rails"),
            },
        }
        for header, rules in _map.items():
            val = hdrs.get(header,"").lower()
            for kw,(cat,label) in rules.items():
                if kw in val:
                    cats[cat].append(label)

        if hdrs.get("X-Generator"):
            gen = hdrs["X-Generator"]
            if "wordpress" in gen.lower(): cats["cms"].append("WordPress")
            if "drupal"    in gen.lower(): cats["cms"].append("Drupal")

        for sh in ("Content-Security-Policy","Strict-Transport-Security",
                   "X-Frame-Options","X-Content-Type-Options","Referrer-Policy",
                   "Permissions-Policy"):
            if hdrs.get(sh):
                cats["security"].append(sh)

        if cf := hdrs.get("CF-Cache-Status") or hdrs.get("CF-Ray"):
            cats["cdn"].append("Cloudflare")
        if hdrs.get("X-Cache","").startswith("Hit from cloudfront"):
            cats["cdn"].append("CloudFront")

    def _parse_html(self, html: str, cats: Dict) -> None:
        h = html.lower()
        _fw = [
            (r"jquery(?:\.min)?\.js",   "javascript","jQuery"),
            (r"react(?:-dom)?",         "javascript","React"),
            (r"angular",                "javascript","Angular"),
            (r"vue(?:\.min)?\.js",      "javascript","Vue.js"),
            (r"bootstrap",              "framework", "Bootstrap"),
            (r"tailwind",               "framework", "Tailwind"),
            (r"laravel",                "framework", "Laravel"),
            (r"wp-content|wp-includes", "cms",       "WordPress"),
            (r"sites/all|/sites/default","cms",      "Drupal"),
            (r"joomla",                 "cms",       "Joomla"),
        ]
        for pat, cat, label in _fw:
            if re.search(pat, h):
                cats[cat].append(label)
        _analytics = [
            (r"google-analytics\.com|gtag",     "Google Analytics"),
            (r"googletagmanager",                "Google Tag Manager"),
            (r"facebook\.com/tr|fbevents",       "Facebook Pixel"),
            (r"matomo|piwik",                    "Matomo"),
        ]
        for pat, label in _analytics:
            if re.search(pat, h):
                cats["analytics"].append(label)

    # ── HTTP header analysis ─────────────────────────────────────
    def http_header_analysis(self, target: str) -> Dict[str, Any]:
        logger.info(f"HTTP header analysis  target={target}")
        REQUIRED = {
            "Content-Security-Policy":   "Mitigates XSS attacks",
            "Strict-Transport-Security": "Enforces HTTPS",
            "X-Frame-Options":           "Prevents clickjacking",
            "X-Content-Type-Options":    "Prevents MIME sniffing",
            "Referrer-Policy":           "Controls Referer leakage",
            "Permissions-Policy":        "Restricts browser feature access",
        }
        result: Dict[str, Any] = {
            "security_headers": {},
            "missing_headers":  [],
            "issues":           [],
            "grade":            "F",
            "tested_url":       None,
        }

        for scheme in ("https","http"):
            url = f"{scheme}://{target}"
            try:
                r = requests.get(url, headers={"User-Agent": _UA},
                                 timeout=_TIMEOUT, verify=False,
                                 allow_redirects=True)
                result["tested_url"] = url

                for hdr, desc in REQUIRED.items():
                    present = hdr in r.headers
                    result["security_headers"][hdr] = {
                        "present":     present,
                        "value":       r.headers.get(hdr),
                        "description": desc,
                    }
                    if not present:
                        result["missing_headers"].append(hdr)

                # Issue: version disclosure in Server header
                srv = r.headers.get("Server","")
                if srv and re.search(r"\d", srv):
                    result["issues"].append(
                        f"Server version disclosed: {srv}"
                    )

                # Issue: wide-open CORS
                if r.headers.get("Access-Control-Allow-Origin") == "*":
                    result["issues"].append("CORS allows all origins (*)")

                # Issue: cookie without Secure/HttpOnly flags
                for cookie in r.cookies:
                    if not cookie.secure:
                        result["issues"].append(
                            f"Cookie '{cookie.name}' lacks Secure flag"
                        )
                    if "httponly" not in str(
                            r.headers.get("Set-Cookie","")).lower():
                        result["issues"].append(
                            f"Cookie '{cookie.name}' may lack HttpOnly flag"
                        )

                missing = len(result["missing_headers"])
                issues  = len(result["issues"])
                score   = max(0, 100 - missing * 10 - issues * 15)
                result["grade"] = ("A" if score>=90 else
                                   "B" if score>=80 else
                                   "C" if score>=70 else
                                   "D" if score>=60 else "F")
                logger.info(f"Header grade={result['grade']}  "
                            f"missing={missing}  issues={issues}")
                return result
            except requests.RequestException:
                continue

        result["error"] = "Could not connect to target"
        return result

    # ── Vulnerability checks ─────────────────────────────────────
    def basic_vulnerability_checks(self, target: str) -> Dict[str, Any]:
        logger.info(f"Vulnerability checks  target={target}")
        result: Dict[str, Any] = {
            "checks_performed": [],
            "issues":           [],
            "warnings":         [],
            "info":             [],
        }

        # SSL/TLS
        result["checks_performed"].append("ssl_tls")
        ssl_r = self._check_ssl(target)
        result["issues"].extend(ssl_r.get("issues",[]))
        result["warnings"].extend(ssl_r.get("warnings",[]))
        result["info"].extend(ssl_r.get("info",[]))

        # Sensitive paths
        result["checks_performed"].append("sensitive_paths")
        exposed = self._check_sensitive_paths(target)
        for url in exposed:
            sev = "issues" if any(x in url for x in (".git","env","config")) else "warnings"
            result[sev].append(f"Exposed path: {url}")

        # HTTP methods
        result["checks_performed"].append("http_methods")
        risky_methods = self._check_http_methods(target)
        for m in risky_methods:
            result["warnings"].append(f"Risky HTTP method enabled: {m}")

        logger.info(f"Vuln checks done  issues={len(result['issues'])}  "
                    f"warnings={len(result['warnings'])}")
        return result

    def _check_ssl(self, target: str) -> Dict[str, List[str]]:
        r: Dict[str, List[str]] = {"issues":[],"warnings":[],"info":[]}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=target) as s:
                    cert = s.getpeercert()
                    tls  = s.version()

                    # TLS version
                    if tls in ("TLSv1","TLSv1.1"):
                        r["issues"].append(f"Deprecated TLS version in use: {tls}")
                    elif tls in ("TLSv1.2","TLSv1.3"):
                        r["info"].append(f"Secure TLS version: {tls}")

                    # Cert expiry
                    not_after = cert.get("notAfter","")
                    if not_after:
                        try:
                            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days = (exp - datetime.utcnow()).days
                            if days < 0:
                                r["issues"].append(
                                    f"SSL certificate EXPIRED {abs(days)} day(s) ago")
                            elif days < 14:
                                r["issues"].append(
                                    f"SSL certificate expires in {days} day(s)!")
                            elif days < 30:
                                r["warnings"].append(
                                    f"SSL certificate expires in {days} day(s)")
                            else:
                                r["info"].append(
                                    f"SSL certificate valid for {days} day(s)")
                        except Exception:
                            pass

                    # Subject Alternative Names
                    sans = [v for t,v in cert.get("subjectAltName",[])
                            if t == "DNS"]
                    r["info"].append(f"SAN count: {len(sans)}")
        except ssl.SSLError as exc:
            r["issues"].append(f"SSL error: {exc}")
        except ConnectionRefusedError:
            r["info"].append("Port 443 not open (HTTPS unavailable)")
        except Exception as exc:
            r["warnings"].append(f"SSL check incomplete: {exc}")
        return r

    def _check_sensitive_paths(self, target: str) -> List[str]:
        paths = [
            "/.git/HEAD", "/.git/config", "/.env", "/.env.local",
            "/config.php", "/wp-config.php.bak", "/robots.txt",
            "/sitemap.xml", "/.htaccess", "/server-status",
            "/admin", "/admin/login", "/phpmyadmin",
            "/.DS_Store", "/crossdomain.xml",
        ]
        exposed: List[str] = []
        for scheme in ("https","http"):
            for path in paths:
                url = f"{scheme}://{target}{path}"
                try:
                    r = requests.get(
                        url, headers={"User-Agent": _UA},
                        timeout=3, verify=False, allow_redirects=False,
                    )
                    if r.status_code == 200:
                        exposed.append(url)
                except Exception:
                    pass
            if exposed:   # found some via this scheme; don't repeat
                break
        return exposed

    def _check_http_methods(self, target: str) -> List[str]:
        risky = []
        for scheme in ("https","http"):
            url = f"{scheme}://{target}/"
            try:
                r = requests.options(
                    url, headers={"User-Agent": _UA},
                    timeout=4, verify=False,
                )
                allow = r.headers.get("Allow","")
                for m in ("TRACE","TRACK","PUT","DELETE","CONNECT"):
                    if m in allow:
                        risky.append(m)
                if risky:
                    break
            except Exception:
                continue
        return risky
