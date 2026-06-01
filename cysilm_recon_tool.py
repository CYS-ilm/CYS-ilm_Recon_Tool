#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════╗
║           CYS-ILM RECONNAISSANCE TOOL  v3.0                       ║
║           Professional Security Assessment Framework              ║
║           Author : CYS-ILM Security Team                          ║
║           License: For Authorized Testing Only                    ║
╚═══════════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import json
import time
import subprocess
from datetime import datetime
from typing import Dict, Any
import warnings

warnings.filterwarnings("ignore")

# ── version metadata ──────────────────────────────────────────────
__version__ = "3.0.0"
__author__  = "CYS-ILM Security Team"
__tool__    = "CYSilm-Recon"

# ── path bootstrap ────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from modules.passive_recon import PassiveReconnaissance
    from modules.active_recon  import ActiveReconnaissance
    from modules.reporting      import ReportGenerator
    from utils.logger           import setup_logger
    from utils.validator        import validate_input, sanitize_target
    from utils.exceptions       import ReconError, ValidationError, PrivilegeError
except ImportError as exc:
    print(f"\n[ERROR] Failed to import modules: {exc}")
    print("        Ensure all files exist and requirements are installed.\n")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────
def print_banner() -> None:
    """Print the ASCII art banner."""
    banner = f"""
\033[36m
 ██████╗██╗   ██╗███████╗    ██╗██╗     ███╗   ███╗
██╔════╝╚██╗ ██╔╝██╔════╝    ██║██║     ████╗ ████║
██║      ╚████╔╝ ███████╗    ██║██║     ██╔████╔██║
██║       ╚██╔╝  ╚════██║    ██║██║     ██║╚██╔╝██║
╚██████╗   ██║   ███████║    ██║███████╗██║ ╚═╝ ██║
 ╚═════╝   ╚═╝   ╚══════╝    ╚═╝╚══════╝╚═╝     ╚═╝
\033[0m
\033[33m  ┌─────────────────────────────────────────────────┐
  │   Reconnaissance Tool  v{__version__}  |  {__author__}
  │   For authorized security testing only
  └─────────────────────────────────────────────────┘\033[0m
"""
    print(banner)


# ─────────────────────────────────────────────────────────────────
def check_root_required(options: Dict[str, Any]) -> None:
    """
    Warn/re-exec with sudo when scans need raw-socket privileges.

    Nmap SYN scans (standard / comprehensive / stealth) require root.
    We detect early and offer to re-launch with sudo so the user isn't
    surprised by a cryptic nmap error mid-scan.
    """
    needs_root = (
        options.get("scan", False) and
        options.get("scan_type", "quick") in ("standard", "comprehensive", "stealth")
    ) or options.get("all", False)

    if not needs_root:
        return

    if os.geteuid() == 0:
        return  # already root

    print("\033[33m[!] This scan mode requires root privileges (raw sockets).\033[0m")
    print("    Re-launching with sudo …\n")
    try:
        args = ["sudo", sys.executable] + sys.argv
        os.execvp("sudo", args)          # replace current process – no return
    except PermissionError:
        raise PrivilegeError(
            "Root privileges required for SYN scanning. "
            "Run: sudo python3 cysilm_recon_tool.py ..."
        )


# ─────────────────────────────────────────────────────────────────
class CYSilmReconTool:
    """Main controller for CYS-ILM reconnaissance operations."""

    def __init__(self, target: str, verbose: bool = False,
                 output_dir: str = "outputs") -> None:
        self.target     = sanitize_target(target)
        self.verbose    = verbose
        self.output_dir = output_dir
        self.logger     = setup_logger("CYSilmRecon", verbose)

        if not validate_input(self.target):
            raise ValidationError(f"Invalid target: '{self.target}'. "
                                  "Provide a valid domain or IP address.")

        self.passive = PassiveReconnaissance(verbose)
        self.active  = ActiveReconnaissance(verbose)

        self.results: Dict[str, Any] = {
            "metadata": {
                "target":        self.target,
                "start_time":    datetime.now().isoformat(),
                "tool_version":  __version__,
                "scan_id":       f"CYSILM-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "operator":      os.environ.get("USER", "unknown"),
                "privileged":    os.geteuid() == 0,
            },
            "passive": {},
            "active":  {},
            "findings":         [],
            "risk_assessment":  {},
        }
        os.makedirs(output_dir, exist_ok=True)

    # ── public API ────────────────────────────────────────────────
    def run(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the full reconnaissance pipeline."""
        self.logger.info(f"Target    : {self.target}")
        self.logger.info(f"Scan ID   : {self.results['metadata']['scan_id']}")
        self.logger.info(f"Privileged: {self.results['metadata']['privileged']}")

        try:
            if options.get("passive", False):
                self._phase("PASSIVE INFORMATION GATHERING",
                            self._run_passive, options)

            if options.get("active", False):
                self._phase("ACTIVE DISCOVERY & ENUMERATION",
                            self._run_active, options)

            self._phase("ANALYSIS & RISK ASSESSMENT",
                        self._analyse_and_score)

            self.results["metadata"].update(
                end_time=datetime.now().isoformat(),
                status="completed"
            )
            self.logger.info("Scan completed successfully.")
            return self.results

        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user.")
            self.results["metadata"]["status"] = "interrupted"
            return self.results
        except Exception as exc:
            self.logger.error(f"Scan failed: {exc}")
            self.results["metadata"].update(status="failed", error=str(exc))
            raise

    # ── private helpers ───────────────────────────────────────────
    def _phase(self, label: str, fn, *args) -> None:
        sep = "═" * 60
        self.logger.info(sep)
        self.logger.info(f"  {label}")
        self.logger.info(sep)
        fn(*args) if args else fn()

    def _run_passive(self, opts: Dict[str, Any]) -> None:
        p = self.results["passive"]
        try:
            if opts.get("whois") or opts.get("all"):
                self.logger.info("WHOIS lookup …")
                p["whois"] = self.passive.whois_lookup(self.target)

            if opts.get("dns") or opts.get("all"):
                self.logger.info("DNS enumeration …")
                p["dns"] = self.passive.dns_enumeration(
                    self.target,
                    record_types=["A","AAAA","MX","TXT","NS","SOA","CNAME","CAA"]
                )

            if opts.get("subdomains") or opts.get("all"):
                self.logger.info("Subdomain discovery …")
                p["subdomains"] = self.passive.subdomain_discovery(
                    self.target,
                    use_crtsh=True,
                    use_otx=False,
                    brute_force=False,
                )

            if opts.get("all"):
                self.logger.info("Reverse IP lookup …")
                p["reverse_lookup"] = self.passive.reverse_ip_lookup(self.target)

                self.logger.info("Email harvesting (headers) …")
                p["email_info"] = self.passive.email_harvest(self.target)

        except Exception as exc:
            self.logger.error(f"Passive phase error: {exc}")

    def _run_active(self, opts: Dict[str, Any]) -> None:
        a = self.results["active"]
        try:
            if opts.get("scan") or opts.get("all"):
                self.logger.info("Port scan …")
                a["port_scan"] = self.active.comprehensive_port_scan(
                    self.target,
                    ports=opts.get("ports", "1-1000"),
                    scan_type=opts.get("scan_type", "quick"),
                    timing_template=opts.get("timing", 3),
                )

            if opts.get("banners") or opts.get("all"):
                self.logger.info("Banner grabbing …")
                open_ports = [
                    p["port"]
                    for p in a.get("port_scan", {}).get("open_ports", [])
                ] or None
                a["banners"] = self.active.banner_grabbing(self.target, open_ports)

            if opts.get("tech") or opts.get("all"):
                self.logger.info("Technology fingerprinting …")
                a["technologies"] = self.active.technology_detection(self.target)

            if opts.get("all"):
                self.logger.info("HTTP security-header analysis …")
                a["http_headers"] = self.active.http_header_analysis(self.target)

                self.logger.info("SSL/TLS & vulnerability checks …")
                a["vulnerability_checks"] = self.active.basic_vulnerability_checks(
                    self.target
                )

        except Exception as exc:
            self.logger.error(f"Active phase error: {exc}")

    def _analyse_and_score(self) -> None:
        findings: list = []
        passive = self.results.get("passive", {})
        active  = self.results.get("active",  {})

        # ── passive findings ──────────────────────────────────────
        if whois := passive.get("whois"):
            if not whois.get("error"):
                findings.append({
                    "severity": "INFO",
                    "category": "Registration",
                    "title":    "WHOIS data retrieved",
                    "description": (
                        f"Registrar: {whois.get('registrar','N/A')} | "
                        f"Age: {whois.get('domain_age_years','?')} yr(s)"
                    ),
                    "recommendation": "Verify registration details are accurate."
                })
                if age := whois.get("domain_age_years"):
                    if age < 1:
                        findings.append({
                            "severity": "MEDIUM",
                            "category": "Registration",
                            "title":    "Recently registered domain (<1 year)",
                            "description": "Young domains are common in phishing.",
                            "recommendation": "Scrutinise domain trust carefully."
                        })

        if dns := passive.get("dns", {}).get("records"):
            total = sum(len(v) for v in dns.values() if isinstance(v, list))
            findings.append({
                "severity": "INFO",
                "category": "DNS",
                "title":    f"{total} DNS records enumerated",
                "description": "Records: " + ", ".join(
                    k for k, v in dns.items() if isinstance(v, list) and v
                ),
                "recommendation": "Disable zone transfers; limit public exposure."
            })
            txt = dns.get("TXT", [])
            if not any("v=spf1" in r for r in txt if isinstance(r, str)):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Email Security",
                    "title":    "Missing SPF record",
                    "description": "No SPF TXT record found – email spoofing risk.",
                    "recommendation": "Add an SPF record to prevent email spoofing."
                })
            if not passive.get("passive", {}).get("dmarc"):
                findings.append({
                    "severity": "LOW",
                    "category": "Email Security",
                    "title":    "DMARC not detected in scan scope",
                    "description": "DMARC enforces email authentication policies.",
                    "recommendation": "Implement a DMARC policy (p=reject)."
                })

        if subs := passive.get("subdomains", {}):
            valid = subs.get("total_valid", 0)
            if valid:
                findings.append({
                    "severity": "INFO",
                    "category": "Infrastructure",
                    "title":    f"{valid} valid subdomain(s) discovered",
                    "description": "Attack surface expanded by exposed subdomains.",
                    "recommendation": "Decommission unused subdomains; use wildcard certs carefully."
                })

        # ── active findings ───────────────────────────────────────
        if ps := active.get("port_scan", {}):
            open_ports = ps.get("open_ports", [])
            if open_ports:
                risky = [p for p in open_ports if p["port"] in (21,23,25,110,143,3389)]
                sev   = "HIGH" if risky else "LOW"
                findings.append({
                    "severity": sev,
                    "category": "Network",
                    "title":    f"{len(open_ports)} open port(s) found",
                    "description": (
                        "Risky services: " +
                        ", ".join(f"{p['port']}/{p['service']}" for p in risky)
                        if risky else "Standard services exposed."
                    ),
                    "recommendation": (
                        "Disable Telnet (23), unencrypted FTP (21); "
                        "use SSH/SFTP. Restrict RDP (3389) to VPN only."
                        if risky else "Apply firewall rules; restrict to needed IPs."
                    )
                })

        if hdrs := active.get("http_headers", {}):
            missing = hdrs.get("missing_headers", [])
            if missing:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Web Security",
                    "title":    f"{len(missing)} security header(s) missing",
                    "description": "Missing: " + ", ".join(missing),
                    "recommendation": (
                        "Add CSP, HSTS, X-Frame-Options, "
                        "X-Content-Type-Options, Referrer-Policy."
                    )
                })
            if grade := hdrs.get("grade"):
                findings.append({
                    "severity": "INFO",
                    "category": "Web Security",
                    "title":    f"HTTP security grade: {grade}",
                    "description": f"Automated header-based grade assigned.",
                    "recommendation": "Aim for grade A or above."
                })

        if vulns := active.get("vulnerability_checks", {}):
            for issue in vulns.get("issues", []):
                findings.append({
                    "severity": "HIGH",
                    "category": "Vulnerability",
                    "title":    issue,
                    "description": "Detected by automated checks.",
                    "recommendation": "Investigate and remediate immediately."
                })
            for warn in vulns.get("warnings", []):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Vulnerability",
                    "title":    warn,
                    "description": "Potential security concern.",
                    "recommendation": "Review and remediate if applicable."
                })

        if techs := active.get("technologies", {}):
            count = sum(len(v) for v in techs.values() if isinstance(v, list))
            if count:
                findings.append({
                    "severity": "INFO",
                    "category": "Fingerprinting",
                    "title":    f"{count} technology/technologies fingerprinted",
                    "description": "; ".join(
                        f"{cat}: {', '.join(v)}"
                        for cat, v in techs.items()
                        if isinstance(v, list) and v
                    ),
                    "recommendation": "Hide/obfuscate version info via server headers."
                })

        if not findings:
            findings.append({
                "severity": "INFO",
                "category": "Scan",
                "title":    "Reconnaissance completed",
                "description": f"Scan finished on {self.target}. No notable issues.",
                "recommendation": "Consider running a broader scan for completeness."
            })

        self.results["findings"] = findings
        self._score_risk(findings)

    def _score_risk(self, findings: list) -> None:
        weights = {"HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}
        score   = sum(weights.get(f.get("severity","INFO"), 0) for f in findings)
        score   = min(score, 100)

        if score >= 40:
            level = "HIGH"
        elif score >= 20:
            level = "MEDIUM"
        elif score >= 5:
            level = "LOW"
        else:
            level = "INFO"

        self.results["risk_assessment"] = {
            "risk_score":  score,
            "risk_level":  level,
            "total_findings": len(findings),
            "high_count":   sum(1 for f in findings if f.get("severity") == "HIGH"),
            "medium_count": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "low_count":    sum(1 for f in findings if f.get("severity") == "LOW"),
            "timestamp":    datetime.now().isoformat(),
        }


# ─────────────────────────────────────────────────────────────────
def build_options(args: argparse.Namespace) -> Dict[str, Any]:
    opts: Dict[str, Any] = {
        "passive":    False,
        "active":     False,
        "whois":      False,
        "dns":        False,
        "subdomains": False,
        "scan":       False,
        "banners":    False,
        "tech":       False,
        "all":        False,
        "ports":      args.ports,
        "scan_type":  args.scan_type,
        "timing":     args.timing,
        "timeout":    args.timeout,
    }

    if args.all:
        opts.update(passive=True, active=True, all=True,
                    whois=True, dns=True, subdomains=True,
                    scan=True, banners=True, tech=True)

    elif args.passive:
        opts.update(passive=True,
                    whois=args.whois or True,
                    dns=args.dns or True,
                    subdomains=args.subdomains or True)

    elif args.active:
        opts.update(active=True,
                    scan=args.scan or True,
                    banners=args.banners or True,
                    tech=args.tech or True)

    elif args.quick:
        opts.update(passive=True, active=True,
                    whois=True, dns=True, scan=True, tech=True,
                    ports="21,22,23,25,53,80,110,143,443,445,993,995,3389,8080,8443",
                    scan_type="quick")

    else:
        # Fine-grained module selection
        if args.whois or args.dns or args.subdomains:
            opts["passive"] = True
            opts["whois"]   = args.whois
            opts["dns"]     = args.dns
            opts["subdomains"] = args.subdomains

        if args.scan or args.banners or args.tech:
            opts["active"]   = True
            opts["scan"]     = args.scan
            opts["banners"]  = args.banners
            opts["tech"]     = args.tech

    # Nothing selected → default to quick passive
    if not opts["passive"] and not opts["active"]:
        opts.update(passive=True, whois=True, dns=True)

    return opts


# ─────────────────────────────────────────────────────────────────
def main() -> int:
    print_banner()

    parser = argparse.ArgumentParser(
        prog="cysilm_recon_tool.py",
        description=f"CYS-ILM Reconnaissance Tool v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Full comprehensive scan (requires sudo for SYN):
    sudo python3 cysilm_recon_tool.py example.com --all --output html

  Passive only:
    python3 cysilm_recon_tool.py example.com --passive --output txt

  Active only (TCP-connect, no sudo needed):
    python3 cysilm_recon_tool.py example.com --active --scan-type quick

  Quick preset:
    python3 cysilm_recon_tool.py example.com --quick --output html

  Custom ports:
    sudo python3 cysilm_recon_tool.py example.com --active --ports 1-65535 --scan-type comprehensive

DISCLAIMER:
  This tool is for AUTHORIZED security testing only.
  Always obtain written permission before scanning any system.
""",
    )

    parser.add_argument("target", help="Target domain or IP address")

    # Scan modes
    m = parser.add_argument_group("Scan Modes")
    me = m.add_mutually_exclusive_group()
    me.add_argument("--all",     action="store_true", help="Full passive + active scan")
    me.add_argument("--passive", action="store_true", help="Passive recon only")
    me.add_argument("--active",  action="store_true", help="Active recon only")
    me.add_argument("--quick",   action="store_true", help="Quick preset (common ports)")

    # Passive modules
    p = parser.add_argument_group("Passive Modules")
    p.add_argument("--whois",      action="store_true")
    p.add_argument("--dns",        action="store_true")
    p.add_argument("--subdomains", action="store_true")

    # Active modules
    a = parser.add_argument_group("Active Modules")
    a.add_argument("--scan",    action="store_true")
    a.add_argument("--banners", action="store_true")
    a.add_argument("--tech",    action="store_true")
    a.add_argument("--ports",     default="1-1000", metavar="RANGE",
                   help="Port range/list (default: 1-1000)")
    a.add_argument("--scan-type", dest="scan_type",
                   choices=["quick","standard","comprehensive","stealth"],
                   default="quick")
    a.add_argument("--timing", type=int, choices=range(0, 6), default=3, metavar="0-5",
                   help="Nmap timing template (default: 3)")

    # Output
    o = parser.add_argument_group("Output")
    o.add_argument("--output",     choices=["txt","html","json","all"], default="txt")
    o.add_argument("--output-dir", default="outputs", metavar="DIR")
    o.add_argument("--no-report",  action="store_true")

    # Misc
    parser.add_argument("--timeout", type=int, default=10, metavar="SEC")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("-q", "--quiet",   action="store_true")
    parser.add_argument("--version", action="version",
                        version=f"CYS-ILM Recon Tool v{__version__}")

    args = parser.parse_args()

    try:
        verbose = (args.verbose > 0) and not args.quiet
        opts    = build_options(args)

        # Privilege check / escalation
        check_root_required(opts)

        tool    = CYSilmReconTool(args.target, verbose, args.output_dir)
        results = tool.run(opts)

        # Reporting
        if not args.no_report:
            reporter = ReportGenerator(results, args.output_dir)
            generated = []

            if args.output in ("txt", "all"):
                generated.append(("Text ", reporter.generate_text_report()))
            if args.output in ("html", "all"):
                generated.append(("HTML ", reporter.generate_html_report()))
            if args.output in ("json", "all"):
                generated.append(("JSON ", reporter.generate_json_report()))

            if not args.quiet:
                print("\n\033[32m Reports saved:\033[0m")
                for fmt, path in generated:
                    print(f"   [{fmt}] {path}")

        if not args.quiet:
            risk = results.get("risk_assessment", {})
            print(f"\n\033[36m Target     :\033[0m {args.target}")
            print(f"\033[36m Risk Level  :\033[0m {risk.get('risk_level','N/A')}  "
                  f"(score {risk.get('risk_score',0)}/100)")
            print(f"\033[36m Findings    :\033[0m {risk.get('total_findings',0)}  "
                  f"[\033[31mH:{risk.get('high_count',0)}\033[0m "
                  f"\033[33mM:{risk.get('medium_count',0)}\033[0m "
                  f"\033[32mL:{risk.get('low_count',0)}\033[0m]")
            print()

        return 0

    except (ValidationError, PrivilegeError) as exc:
        print(f"\n\033[31m[ERROR]\033[0m {exc}\n")
        return 1
    except KeyboardInterrupt:
        print("\n\033[33m[!] Interrupted.\033[0m\n")
        return 1
    except Exception as exc:
        print(f"\n\033[31m[FATAL]\033[0m {exc}\n")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
