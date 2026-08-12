"""Optional RDAP/whois enrichment for source IPs (from viewer-mark-3)."""

from __future__ import annotations

import ipaddress

import pandas as pd


def ip_class(ip: str) -> str:
    try:
        o = ipaddress.ip_address(ip)
        if o.is_private:
            return "PRIVATE"
        if o.is_loopback:
            return "LOOPBACK"
        if o.is_reserved:
            return "RESERVED"
        if o.is_link_local:
            return "LINK_LOCAL"
        if o.is_multicast:
            return "MULTICAST"
        return "PUBLIC"
    except ValueError:
        return "INVALID"


def _rdap_lookup(ip: str) -> dict:
    try:
        from ipwhois import IPWhois

        return IPWhois(ip).lookup_rdap()
    except Exception:
        return {}


def _extract_asn_geo(rdap: dict) -> tuple[str, str]:
    asn_name = (rdap.get("network") or {}).get("name") or rdap.get("asn_description") or "UNKNOWN"
    country = (rdap.get("network") or {}).get("country") or rdap.get("asn_country_code") or "UNK"
    return asn_name, country


def enrich_ips(ips: list[str], max_lookups: int = 10) -> pd.DataFrame:
    """RDAP-enrich a list of IPs with ASN name / country, capped at `max_lookups`
    live network calls (public IPs only) to keep the app responsive."""
    rows = []
    lookups_done = 0

    for ip in ips:
        cls = ip_class(ip)
        if cls != "PUBLIC":
            rows.append({"sourceIPAddress": ip, "asn_name": cls, "country": ""})
            continue

        if lookups_done >= max_lookups:
            rows.append({"sourceIPAddress": ip, "asn_name": f"LOOKUP_SKIPPED_MAX{max_lookups}", "country": ""})
            continue

        rdap = _rdap_lookup(ip)
        asn_name, country = _extract_asn_geo(rdap)
        rows.append({"sourceIPAddress": ip, "asn_name": asn_name, "country": country})
        lookups_done += 1

    return pd.DataFrame(rows)
