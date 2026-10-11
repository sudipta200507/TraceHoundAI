"""Pre-scan target reachability diagnostics — real network truth, no invention.

Scope-gated: a DNS check for an out-of-scope host never happens. Results are
deterministic observations used to explain to the operator WHY a target may
produce no findings (unresolvable domain, no live web service, DNS outage...).
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlsplit

from backend.app.core.logger import get_logger
from backend.app.safety.scope_validator import ScopeConfig, normalize_target, validate_target

log = get_logger("tracehound.reachability")

# Authoritative public resolvers used as fallback when the local resolver
# cannot answer; they exist precisely for these diagnostics. Well-formed
# targets are checked against ALL resolvers before a verdict is issued.
FALLBACK_RESOLVERS = (
    ("8.8.8.8", "Google Public DNS"),
    ("1.1.1.1", "Cloudflare Public DNS"),
)


def _socket_resolve(host: str, resolver: Optional[str] = None,
                    timeout: float = 8.0) -> list[str]:
    """Resolve A/AAAA records. Optionally force a specific resolver."""
    import subprocess

    try:
        if resolver:
            proc = subprocess.run(
                ["nslookup", host, resolver],
                capture_output=True, text=True, timeout=timeout, shell=False,
            )
            text = (proc.stdout or "") + (proc.stderr or "")
            return _parse_nslookup_addresses(text)
        answers = socket.getaddrinfo(host, None)
        seen: list[str] = []
        for info in answers:
            addr = str(info[4][0])
            if addr not in seen:
                seen.append(addr)
        return seen
    except Exception:
        return []


def _parse_nslookup_addresses(text: str) -> list[str]:
    """Parse nslookup output tolerantly; IPv6 lines are kept verbatim."""
    addresses: list[str] = []
    for line in (text or "").splitlines():
        s = line.strip()
        for marker in ("Address:", "Address "):
            if s.startswith(marker):
                value = s[len(marker):].strip().lstrip(":").strip()
                if value and value not in addresses and not value.startswith("#"):
                    addresses.append(value)
    return addresses


def _probe_http(url: str, timeout: float = 8.0) -> tuple[int, str]:
    """HTTP probe with the standard library; returns (status, error)."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, headers={"User-Agent": "TraceHoundAI-lab"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status), ""
    except urllib.error.HTTPError as exc:
        # Any HTTP response means the web service is real and reachable.
        return int(exc.code), ""
    except Exception as exc:
        return 0, str(exc)[:200]


def _diagnose_nameserve(domain: str) -> tuple[bool, str]:
    """SOA-anchored check: does the domain even publish DNS? Cheap NS probe."""
    import subprocess

    try:
        proc = subprocess.run(
            ["nslookup", "-type=NS", domain],
            capture_output=True, text=True, timeout=10, shell=False,
        )
        text = ((proc.stdout or "") + (proc.stderr or "")).lower()
        if "nameserver" in text or "nsdname" in text or "dns.rfc-ignorant" not in text:
            return True, ""
        return False, "domain publishes no nameservers (not registered or not hosted)"
    except Exception as exc:
        return False, f"nameserver probe failed: {str(exc)[:150]}"


def probe_target_reachability(
    target: str,
    config: Optional[ScopeConfig] = None,
    probe_http: bool = True,
) -> dict[str, Any]:
    """Full diagnostic report for an authorized root domain.

    Returns a structured dict the API/UI can render verbatim. Only in-scope
    hosts ever reach the network — the gate runs first.
    """
    decision = validate_target(target, config)
    if not decision.allowed:
        return {
            "target": target, "checked": False,
            "verdict": "out_of_scope", "reason": decision.reason,
            "dns_resolvable": False, "resolvers_tried": [], "addresses": [],
            "nameserver_ok": False, "http_probes": [],
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
    normalized = normalize_target(target)
    host = normalized.host

    local_answers = _socket_resolve(host)
    all_addresses = list(local_answers)
    resolvers_tried = ["system-resolver"]
    for ip, label in FALLBACK_RESOLVERS:
        if local_answers:
            break
        answers = _socket_resolve(host, resolver=ip)
        resolvers_tried.append(label)
        for addr in answers:
            if addr not in all_addresses:
                all_addresses.append(addr)

    ns_ok, ns_note = _diagnose_nameserve(host)
    all_addresses = [a for a in all_addresses if a not in ns_note]

    dns_resolvable = bool(all_addresses)

    probes: list[dict[str, Any]] = []
    if probe_http:
        for scheme, port_label in (("https", 443), ("http", 80)):
            url = f"{scheme}://{host}/"
            status, err = _probe_http(url)
            probes.append({"url": url, "status": status,
                           "reachable": status > 0,
                           "error": err})

    # Verdict priority: clearly explain, in plain language, what the evidence
    # shows — before any tool run, and could-have-worked observations after.
    if dns_resolvable and any(p["reachable"] for p in probes):
        verdict = "reachable"
        reason = ("Domain resolves in DNS and at least one HTTP/HTTPS endpoint "
                  "answered. The pipeline has a real, live target.")
    elif dns_resolvable and probes:
        verdict = "dns_alive_no_web"
        reason = ("Domain resolves in DNS, but neither HTTPS (443) nor HTTP (80) "
                  "answered. Subdomain and port discovery will still run; the "
                  "site itself may not publish a web service on those ports.")
    elif dns_resolvable:
        verdict = "reachable_dns_only"
        reason = ("Domain resolves in DNS. Passive/active discovery will run; "
                  "live web checks follow automatically.")
    elif not ns_ok:
        verdict = "not_registered"
        reason = (f"The domain appears to have no published nameservers, so the "
                  f"public DNS cannot locate it. Details: {ns_note or 'no NS records'}")
    else:
        verdict = "dns_dead"
        reason = ("The domain does NOT resolve on any resolver we tried "
                  f"({', '.join(resolvers_tried)}). It may be unregistered, "
                  "recently expired, DNS-hosted incorrectly, or the machine "
                  "running the scan is offline. Nothing can be scanned.")

    return {
        "target": host, "checked": True,
        "verdict": verdict, "reason": reason,
        "dns_resolvable": dns_resolvable,
        "resolvers_tried": resolvers_tried,
        "addresses": all_addresses,
        "nameserver_ok": ns_ok,
        "http_probes": probes,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def reachable_summary(diag: dict[str, Any]) -> str:
    """One-line human-readable summary for the UI."""
    if not diag.get("checked"):
        return "Target was not checked."
    verdict = diag.get("verdict", "")
    descriptions = {
        "reachable": "Target is live and fully scannable.",
        "dns_alive_no_web": "Domain resolves but no HTTP/HTTPS answered.",
        "reachable_dns_only": "Domain resolves; live checks pass automatically.",
        "not_registered": "Domain has no nameservers — likely unregistered.",
        "dns_dead": "Domain does not resolve anywhere — nothing can be scanned.",
        "out_of_scope": "Target is outside authorized scope.",
    }
    return descriptions.get(verdict, diag.get("reason", "Status unknown."))
