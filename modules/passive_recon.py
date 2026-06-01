"""
Passive Reconnaissance Module – CYS-ILM v3.0
Collects open-source intelligence without sending packets to the target.
"""

import socket
import time
import re
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
import whois
import dns.resolver
import dns.reversename

logger = logging.getLogger(__name__)

# ── safe request defaults ─────────────────────────────────────────
_HEADERS = {
    "User-Agent": "CYS-ILM-Recon/3.0 (security-research)",
    "Accept":     "application/json",
}
_REQ_TIMEOUT = 8   # seconds


class PassiveReconnaissance:
    """Passive OSINT gathering: WHOIS, DNS, subdomains, reverse IP."""

    def __init__(self, verbose: bool = False) -> None:
        if verbose:
            logger.setLevel(logging.DEBUG)

        self.resolver             = dns.resolver.Resolver()
        self.resolver.timeout     = 3
        self.resolver.lifetime    = 6
        self._last_req: Dict[str, float] = {}
        self._req_delay           = 1.5   # seconds between API calls

        self.common_subdomains = [
            "www","mail","ftp","smtp","pop","imap","admin","blog","webmail",
            "portal","cpanel","whm","webdisk","ns1","ns2","test","dev",
            "staging","api","secure","vpn","m","mobile","static","cdn",
            "assets","support","help","status","login","shop","store",
            "remote","intranet","internal","gateway","proxy","dns","mx",
        ]

    # ── WHOIS ────────────────────────────────────────────────────
    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        logger.info(f"WHOIS lookup → {domain}")
        try:
            info = whois.whois(self._clean(domain))
            result: Dict[str, Any] = {
                "domain_name":      self._safe(info.domain_name),
                "registrar":        info.registrar,
                "whois_server":     info.whois_server,
                "creation_date":    self._safe(info.creation_date),
                "expiration_date":  self._safe(info.expiration_date),
                "updated_date":     self._safe(info.updated_date),
                "name_servers":     self._safe(info.name_servers),
                "status":           self._safe(info.status),
                "emails":           self._safe(info.emails),
                "dnssec":           getattr(info, "dnssec", None),
                "org":              getattr(info, "org", None),
                "country":          getattr(info, "country", None),
            }
            # Compute domain age
            raw_creation = info.creation_date
            if isinstance(raw_creation, list):
                raw_creation = raw_creation[0]
            if hasattr(raw_creation, "year"):
                result["domain_age_years"] = datetime.now().year - raw_creation.year
            logger.info(f"WHOIS complete  registrar={result.get('registrar')}")
            return result
        except Exception as exc:
            logger.warning(f"WHOIS failed: {exc}")
            return {"error": str(exc), "domain": domain}

    # ── DNS ──────────────────────────────────────────────────────
    def dns_enumeration(self, domain: str,
                        record_types: Optional[List[str]] = None) -> Dict[str, Any]:
        if record_types is None:
            record_types = ["A","AAAA","MX","TXT","NS","SOA","CNAME","CAA"]
        logger.info(f"DNS enumeration → {domain}  types={record_types}")

        records: Dict[str, List[str]] = {}
        for rtype in record_types:
            records[rtype] = self._query_dns(domain, rtype)

        # DMARC is a special sub-domain query
        dmarc = self._query_dns(f"_dmarc.{domain}", "TXT")
        if any("v=DMARC1" in r for r in dmarc):
            records["DMARC"] = [r for r in dmarc if "v=DMARC1" in r]

        ip_addrs = records.get("A",[]) + records.get("AAAA",[])
        total    = sum(len(v) for v in records.values())

        logger.info(f"DNS complete  total_records={total}")
        return {
            "domain":    domain,
            "records":   records,
            "summary":   {
                "total_records":        total,
                "record_types_found":   [k for k,v in records.items() if v],
                "has_mx":               bool(records.get("MX")),
                "has_txt":              bool(records.get("TXT")),
                "has_dmarc":            bool(records.get("DMARC")),
                "nameservers":          records.get("NS",[]),
                "ip_addresses":         ip_addrs,
            },
            "timestamp": datetime.now().isoformat(),
        }

    def _query_dns(self, name: str, rtype: str) -> List[str]:
        try:
            answers = self.resolver.resolve(name, rtype, lifetime=4)
            results = []
            for rdata in answers:
                if rtype == "MX":
                    results.append(f"{rdata.preference} {rdata.exchange}")
                elif rtype == "SOA":
                    results.append(
                        f"mname={rdata.mname} rname={rdata.rname} "
                        f"serial={rdata.serial}"
                    )
                else:
                    results.append(str(rdata))
            return results
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except dns.resolver.Timeout:
            return ["[TIMEOUT]"]
        except Exception as exc:
            logger.debug(f"DNS {rtype} query for {name}: {exc}")
            return []

    # ── Subdomain discovery ───────────────────────────────────────
    def subdomain_discovery(self, domain: str, **kwargs) -> Dict[str, Any]:
        logger.info(f"Subdomain discovery → {domain}")
        all_subs: Set[str] = set()
        sources:  Dict[str, List[str]] = {}

        if kwargs.get("use_crtsh", True):
            found = self._crtsh(domain)
            sources["crt_sh"] = sorted(found)
            all_subs.update(found)
            logger.debug(f"crt.sh  → {len(found)} subdomains")

        found = self._common_subdomain_check(domain)
        sources["brute_common"] = sorted(found)
        all_subs.update(found)
        logger.debug(f"brute   → {len(found)} subdomains")

        unique = sorted(all_subs)[:100]   # cap at 100 for speed
        logger.info(f"Validating {len(unique)} unique candidates …")

        validated: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=15) as pool:
            futures = {pool.submit(self._validate_sub, s): s for s in unique}
            for fut in as_completed(futures):
                sub = futures[fut]
                try:
                    ok, ip = fut.result(timeout=4)
                    if ok:
                        validated.append({
                            "subdomain":  sub,
                            "ip_address": ip,
                            "sources":    [k for k,v in sources.items() if sub in v],
                        })
                except Exception:
                    pass

        validated.sort(key=lambda x: x["subdomain"])
        logger.info(f"Subdomain discovery complete  valid={len(validated)}")
        return {
            "domain":              domain,
            "total_discovered":    len(unique),
            "total_valid":         len(validated),
            "sources":             {k: len(v) for k,v in sources.items()},
            "validated_subdomains": validated,
            "by_ip":               self._group_by_ip(validated),
            "timestamp":           datetime.now().isoformat(),
        }

    def _crtsh(self, domain: str) -> Set[str]:
        self._rate_limit("crtsh")
        try:
            r = requests.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers=_HEADERS,
                timeout=_REQ_TIMEOUT,
            )
            if r.status_code != 200:
                return set()
            found: Set[str] = set()
            for entry in r.json():
                for name in entry.get("name_value","").split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(f".{domain}") or name == domain:
                        found.add(name)
            return found
        except Exception as exc:
            logger.debug(f"crt.sh error: {exc}")
            return set()

    def _common_subdomain_check(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        for sub in self.common_subdomains:
            fqdn = f"{sub}.{domain}"
            try:
                socket.setdefaulttimeout(1.5)
                socket.gethostbyname(fqdn)
                found.add(fqdn)
            except Exception:
                pass
        socket.setdefaulttimeout(None)
        return found

    def _validate_sub(self, sub: str) -> Tuple[bool, Optional[str]]:
        try:
            socket.setdefaulttimeout(2)
            ip = socket.gethostbyname(sub)
            return True, ip
        except Exception:
            return False, None
        finally:
            socket.setdefaulttimeout(None)

    # ── Reverse IP ───────────────────────────────────────────────
    def reverse_ip_lookup(self, target: str) -> Dict[str, Any]:
        logger.info(f"Reverse IP lookup → {target}")
        try:
            ip = socket.gethostbyname(target) if not self._is_ip(target) else target
            # PTR record
            ptr: List[str] = []
            try:
                rev = dns.reversename.from_address(ip)
                answers = self.resolver.resolve(rev, "PTR", lifetime=4)
                ptr = [str(a) for a in answers]
            except Exception:
                pass

            return {
                "ip_address":     ip,
                "ptr_records":    ptr,
                "timestamp":      datetime.now().isoformat(),
            }
        except Exception as exc:
            logger.warning(f"Reverse IP failed: {exc}")
            return {"error": str(exc), "target": target}

    # ── Email harvest (MX / header) ──────────────────────────────
    def email_harvest(self, domain: str) -> Dict[str, Any]:
        """Gather email-related DNS intelligence (MX, SPF, DMARC, DKIM)."""
        logger.info(f"Email intelligence → {domain}")
        mx      = self._query_dns(domain, "MX")
        txt     = self._query_dns(domain, "TXT")
        spf     = next((r for r in txt if "v=spf1" in r), None)
        dmarc   = self._query_dns(f"_dmarc.{domain}", "TXT")
        dkim_selectors = ["default","google","k1","mail","dkim","selector1","selector2"]
        dkim_found: List[str] = []
        for sel in dkim_selectors:
            res = self._query_dns(f"{sel}._domainkey.{domain}", "TXT")
            if res and not res[0].startswith("["):
                dkim_found.append(f"{sel}: {res[0][:80]}…")
        return {
            "mx_records": mx,
            "spf":        spf,
            "dmarc":      dmarc[0] if dmarc else None,
            "dkim":       dkim_found,
        }

    # ── helpers ───────────────────────────────────────────────────
    def _clean(self, domain: str) -> str:
        if "://" in domain:
            parsed = urlparse(domain)
            domain = parsed.netloc or parsed.path
        return domain.strip().lower().split("/")[0]

    def _safe(self, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, list):
            return [str(v) for v in value if v is not None]
        return str(value)

    def _is_ip(self, addr: str) -> bool:
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False

    def _rate_limit(self, key: str) -> None:
        now     = time.monotonic()
        elapsed = now - self._last_req.get(key, 0)
        if elapsed < self._req_delay:
            time.sleep(self._req_delay - elapsed)
        self._last_req[key] = time.monotonic()

    def _group_by_ip(self, subs: List[Dict]) -> Dict[str, List[str]]:
        groups: Dict[str, List[str]] = {}
        for s in subs:
            ip = s.get("ip_address")
            if ip:
                groups.setdefault(ip, []).append(s["subdomain"])
        return groups
