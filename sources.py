"""
sources.py
==========
ThreatLens intelligence sources.

Responsibility (and ONLY responsibility) of this module:
  - Individual external intelligence source functions
  - The SOURCE_REGISTRY that exposes them to app.py

Design contract
----------------
Every source function:
  * takes a single argument: `target` (raw string — IP, domain, or URL)
  * returns a dictionary with this exact shape:

        {
            "source":  str,            # human-readable source name
            "status":  "success"|"error",
            "summary": str | None,     # one-line human summary (for Gemini + UI)
            "data":    dict,           # structured, source-specific payload
            "error":   str | None,     # populated when status == "error"
        }

  * never raises — all exceptions are caught and turned into an
    {"status": "error", "error": "..."} result, so orchestration in
    app.py never has to special-case a broken source.

Adding a new source
--------------------
1. Write a new function `get_<name>(target) -> dict` following the
   contract above.
2. Add it to SOURCE_REGISTRY at the bottom of this file.
That's it — app.py, the UI, and the results renderer all iterate over
SOURCE_REGISTRY generically and require ZERO changes.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import whois  # python-whois


# --------------------------------------------------------------------------
# Shared helpers (internal use only — not part of the public source API)
# --------------------------------------------------------------------------

def _get_api_key(name: str) -> str | None:
    """
    Resolve an API key from Streamlit secrets (if available) or the
    environment. Kept dependency-light: st.secrets is only touched if
    streamlit + a secrets.toml are actually present.
    """
    try:
        import streamlit as st  # local import: sources.py stays UI-agnostic

        if name in st.secrets:
            return st.secrets[name]
    except Exception:
        pass
    return os.environ.get(name)


def _extract_host(target: str) -> tuple[str, str]:
    """
    Given a raw target (IP / domain / URL), return (host, host_type)
    where host_type is "ip" or "domain".
    """
    target = target.strip()

    # Bare IP address
    try:
        ipaddress.ip_address(target)
        return target, "ip"
    except ValueError:
        pass

    # URL -> pull hostname out
    if "://" in target:
        host = urlparse(target).hostname or target
    else:
        host = target

    try:
        ipaddress.ip_address(host)
        return host, "ip"
    except (ValueError, TypeError):
        pass

    return host, "domain"


def _raw_whois_query(query: str, whois_server: str, timeout: int = 10) -> str:
    """Minimal raw WHOIS (port 43) client — used for IP allocation lookups."""
    with socket.create_connection((whois_server, 43), timeout=timeout) as sock:
        sock.send((query + "\r\n").encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    return response.decode(errors="ignore")


def _empty_result(source_name: str) -> dict:
    return {
        "source": source_name,
        "status": "error",
        "summary": None,
        "data": {},
        "error": None,
    }


# --------------------------------------------------------------------------
# Source: VirusTotal
# --------------------------------------------------------------------------

def get_virustotal(target: str) -> dict:
    """
    Collect VirusTotal intelligence for an IP, domain, or URL.
    Uses VT API v3. Requires env var / secret: VT_API_KEY.
    Returns a structured dictionary (see module docstring for contract).
    """
    result = _empty_result("VirusTotal")

    api_key = _get_api_key("VT_API_KEY")
    if not api_key:
        result["error"] = "Missing VT_API_KEY (set as env var or Streamlit secret)."
        return result

    headers = {"x-apikey": api_key}
    target_clean = target.strip()

    try:
        if "://" in target_clean:
            # --- URL target: VT identifies URLs by a url-safe base64 id ---
            url_id = base64.urlsafe_b64encode(target_clean.encode()).decode().strip("=")
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 404:
                # Not analyzed yet -> submit it, then poll the analysis once.
                submit = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": target_clean},
                    timeout=15,
                )
                submit.raise_for_status()
                analysis_id = submit.json()["data"]["id"]
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                    timeout=15,
                )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("stats") or attrs.get("last_analysis_stats", {})
            extra = {
                "categories": attrs.get("categories"),
                "title": attrs.get("title"),
            }
        else:
            # --- IP or domain target ---
            host, host_type = _extract_host(target_clean)
            endpoint = "ip_addresses" if host_type == "ip" else "domains"
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/{endpoint}/{host}",
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            extra = {
                "reputation": attrs.get("reputation"),
                "categories": attrs.get("categories"),
                "as_owner": attrs.get("as_owner"),
                "country": attrs.get("country"),
            }

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        result["status"] = "success"
        result["data"] = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "last_analysis_stats": stats,
            **extra,
        }

        if malicious > 0:
            result["summary"] = f"{malicious} security vendor(s) flagged this as MALICIOUS."
        elif suspicious > 0:
            result["summary"] = f"{suspicious} vendor(s) flagged this as suspicious."
        else:
            result["summary"] = "No vendors flagged this target as malicious."

    except requests.exceptions.HTTPError as e:
        result["error"] = f"VirusTotal HTTP error: {e}"
    except requests.exceptions.RequestException as e:
        result["error"] = f"VirusTotal request failed: {e}"
    except Exception as e:  # never let a source crash the app
        result["error"] = f"Unexpected VirusTotal error: {e}"

    return result


# --------------------------------------------------------------------------
# Source: WHOIS
# --------------------------------------------------------------------------

def get_whois(target: str) -> dict:
    """
    Collect WHOIS registration intelligence for an IP, domain, or URL
    (URLs/IPs are reduced to their host first). No API key required.
    Returns a structured dictionary (see module docstring for contract).
    """
    result = _empty_result("WHOIS")
    host, host_type = _extract_host(target)

    try:
        data = _whois_ip(host) if host_type == "ip" else _whois_domain(host)
        result["status"] = "success"
        result["data"] = data
        result["summary"] = data.get("summary")
    except Exception as e:
        result["error"] = f"WHOIS lookup failed: {e}"

    return result


def _whois_domain(domain: str) -> dict:
    w = whois.whois(domain)

    creation = w.creation_date
    if isinstance(creation, list):
        creation = creation[0]
    expiration = w.expiration_date
    if isinstance(expiration, list):
        expiration = expiration[0]

    age_days = None
    if isinstance(creation, datetime):
        now = datetime.now(timezone.utc) if creation.tzinfo else datetime.utcnow()
        try:
            age_days = (now - creation).days
        except Exception:
            age_days = None

    if age_days is not None and age_days < 30:
        summary = f"Domain registered very recently ({age_days} days ago) — common risk indicator."
    elif age_days is not None:
        summary = f"Domain age: {age_days} days. Registrar: {w.registrar or 'unknown'}."
    else:
        summary = f"Registrar: {w.registrar or 'unknown'}."

    return {
        "registrar": w.registrar,
        "creation_date": str(creation) if creation else None,
        "expiration_date": str(expiration) if expiration else None,
        "age_days": age_days,
        "name_servers": w.name_servers,
        "org": getattr(w, "org", None),
        "country": getattr(w, "country", None),
        "summary": summary,
    }


def _whois_ip(ip: str) -> dict:
    raw = None
    try:
        raw = _raw_whois_query(ip, "whois.arin.net")
    except Exception:
        raw = None

    data = {"raw_excerpt": (raw[:1500] if raw else None), "summary": None}

    if raw:
        org_match = re.search(r"(?:OrgName|Organization|org-name):\s*(.+)", raw, re.IGNORECASE)
        country_match = re.search(r"Country:\s*(.+)", raw, re.IGNORECASE)
        net_match = re.search(r"(?:NetName|netname):\s*(.+)", raw, re.IGNORECASE)

        if org_match:
            data["organization"] = org_match.group(1).strip()
        if country_match:
            data["country"] = country_match.group(1).strip()
        if net_match:
            data["net_name"] = net_match.group(1).strip()

        data["summary"] = f"IP allocated to {data.get('organization', 'an unknown organization')}."
    else:
        data["summary"] = "No WHOIS allocation data returned."

    return data


# --------------------------------------------------------------------------
# Source Registry
# --------------------------------------------------------------------------
# app.py iterates over this dict generically — adding a new intel source
# requires ONLY writing a get_<name>(target) function above and adding it
# here. No changes to UI, orchestration, or rendering code are needed.

SOURCE_REGISTRY: dict[str, callable] = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
