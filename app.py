"""
app.py
======
ThreatLens — Streamlit front end.

Responsibility (and ONLY responsibility) of this module:
  - Streamlit UI
  - User input handling
  - Validation flow
  - Source orchestration (calling everything in sources.SOURCE_REGISTRY)
  - Gemini API prompt generation + call
  - Final results display

All external intelligence collection lives in sources.py. This file never
talks to VirusTotal or WHOIS directly — it only calls whatever is
registered in sources.SOURCE_REGISTRY, so new sources plug in with zero
changes here.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from urllib.parse import urlparse

import streamlit as st

from sources import SOURCE_REGISTRY

# --------------------------------------------------------------------------
# Page config
# --------------------------------------------------------------------------

st.set_page_config(
    page_title="ThreatLens",
    page_icon="🛡️",
    layout="centered",
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def classify_target(raw: str) -> tuple[str | None, str | None]:
    """
    Classify user input as 'ip', 'domain', or 'url'.
    Returns (target_type, error_message). target_type is None on failure.
    """
    value = raw.strip()
    if not value:
        return None, "Please enter an IP address, domain, or URL."

    # IP address
    try:
        ipaddress.ip_address(value)
        return "ip", None
    except ValueError:
        pass

    # URL (must have a scheme)
    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return "url", None
        return None, "That looks like a URL but isn't well-formed (use http:// or https://)."

    # Domain
    if DOMAIN_RE.match(value):
        return "domain", None

    return None, "Input doesn't look like a valid IP address, domain, or URL."


# --------------------------------------------------------------------------
# Orchestration — calls every registered source generically
# --------------------------------------------------------------------------

def run_all_sources(target: str) -> list[dict]:
    """
    Iterate SOURCE_REGISTRY and call each source function on `target`.
    Returns a list of result dicts (see sources.py contract). A source
    that isn't registered here requires no orchestration changes — this
    loop already picks it up automatically.
    """
    results = []
    for name, func in SOURCE_REGISTRY.items():
        with st.spinner(f"Querying {name}..."):
            try:
                results.append(func(target))
            except Exception as e:  # belt-and-braces; sources shouldn't raise
                results.append(
                    {
                        "source": name,
                        "status": "error",
                        "summary": None,
                        "data": {},
                        "error": f"Source crashed unexpectedly: {e}",
                    }
                )
    return results


def compute_risk_level(results: list[dict]) -> tuple[str, str]:
    """
    Very small heuristic risk aggregator based on VirusTotal counts.
    Returns (level, css_color) where level in {"High", "Medium", "Low", "Unknown"}.
    """
    vt = next((r for r in results if r.get("source") == "VirusTotal"), None)
    if not vt or vt.get("status") != "success":
        return "Unknown", "#888888"

    data = vt.get("data", {})
    malicious = data.get("malicious", 0) or 0
    suspicious = data.get("suspicious", 0) or 0

    if malicious >= 3:
        return "High", "#d33"
    if malicious > 0 or suspicious >= 3:
        return "Medium", "#e6a817"
    return "Low", "#2e9e44"


# --------------------------------------------------------------------------
# Gemini — prompt generation + API call
# --------------------------------------------------------------------------

def build_gemini_prompt(target: str, target_type: str, results: list[dict]) -> str:
    """Construct a grounded prompt for Gemini using only collected intel."""
    payload = json.dumps(results, indent=2, default=str)
    return f"""You are a cybersecurity threat analyst. Analyze the following raw
intelligence collected about a target and produce a concise, factual
assessment. Do not invent data that isn't present in the JSON below.

Target: {target}
Target type: {target_type}

Raw intelligence (JSON, one object per source):
{payload}

Respond with:
1. A one-line verdict (Safe / Suspicious / Malicious / Inconclusive) with a short reason.
2. 2-4 bullet points explaining the key evidence from the sources above.
3. One practical recommendation for the user.

Keep the whole response under 150 words. If a source errored or has no
data, note that briefly rather than guessing.
"""


def call_gemini(prompt: str) -> tuple[str | None, str | None]:
    """
    Call the Gemini API. Returns (text, error). Requires env var / secret
    GEMINI_API_KEY. Uses the google-generativeai SDK, imported lazily so
    the app can still run source lookups even if the package or key is
    missing.
    """
    api_key = None
    try:
        if "GEMINI_API_KEY" in st.secrets:
            api_key = st.secrets["GEMINI_API_KEY"]
    except Exception:
        pass
    api_key = api_key or os.environ.get("GEMINI_API_KEY")

    if not api_key:
        return None, "Missing GEMINI_API_KEY (set as env var or Streamlit secret)."

    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        # gemini-3.6-flash: current stable, production-recommended model
        # (gemini-2.0-flash was retired June 1, 2026; gemini-2.5-flash is
        # scheduled to retire Oct 16, 2026 — avoid pinning to either).
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
        )
        return response.text, None
    except Exception as e:
        return None, f"Gemini call failed: {e}"


# --------------------------------------------------------------------------
# Rendering — generic over whatever sources ran, no per-source branching
# --------------------------------------------------------------------------

def render_risk_badge(level: str, color: str) -> None:
    st.markdown(
        f"""
        <div style="display:inline-block;padding:6px 16px;border-radius:20px;
                    background-color:{color};color:white;font-weight:600;
                    font-size:0.95rem;">
            Risk level: {level}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_source_results(results: list[dict]) -> None:
    st.subheader("Source details")
    for r in results:
        status_icon = "✅" if r.get("status") == "success" else "⚠️"
        with st.expander(f"{status_icon} {r.get('source', 'Unknown source')}"):
            if r.get("status") == "success":
                if r.get("summary"):
                    st.markdown(f"**Summary:** {r['summary']}")
                st.json(r.get("data", {}))
            else:
                st.error(r.get("error") or "Unknown error.")


# --------------------------------------------------------------------------
# Main UI
# --------------------------------------------------------------------------

def main() -> None:
    st.title("🛡️ ThreatLens")
    st.caption("Quick-look threat intelligence for IPs, domains, and URLs — powered by VirusTotal, WHOIS, and Gemini.")

    with st.sidebar:
        st.header("About")
        st.write(
            "ThreatLens aggregates intelligence from registered sources "
            "and asks Gemini to summarize the findings. Currently registered "
            "sources:"
        )
        for name in SOURCE_REGISTRY:
            st.write(f"• {name}")
        st.divider()
        st.caption(
            "API keys (VT_API_KEY, GEMINI_API_KEY) are read from environment "
            "variables or Streamlit secrets — nothing is entered here."
        )

    target_raw = st.text_input(
        "IP address, domain, or URL",
        placeholder="e.g. 8.8.8.8, example.com, or https://example.com/path",
    )
    analyze_clicked = st.button("Analyze", type="primary")

    if not analyze_clicked:
        return

    target_type, err = classify_target(target_raw)
    if err:
        st.error(err)
        return

    target = target_raw.strip()
    st.info(f"Detected target type: **{target_type.upper()}**")

    # 1) Orchestrate all registered sources generically
    results = run_all_sources(target)

    # 2) Heuristic risk badge from collected data
    level, color = compute_risk_level(results)
    render_risk_badge(level, color)
    st.write("")

    # 3) Gemini assessment grounded in the collected intel
    st.subheader("AI assessment")
    prompt = build_gemini_prompt(target, target_type, results)
    with st.spinner("Asking Gemini for an assessment..."):
        text, gemini_err = call_gemini(prompt)
    if gemini_err:
        st.warning(gemini_err)
    else:
        st.markdown(text)

    st.write("")

    # 4) Raw per-source results, rendered generically
    render_source_results(results)


if __name__ == "__main__":
    main()
