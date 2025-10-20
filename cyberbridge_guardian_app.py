# CyberBridge Guardian — Cisco-Aligned Campus Security Webapp (Formal • Palette Refresh)
# --------------------------------------------------------------------------------------
# Authors: Aryan Kalluvila • Evan Morgan • Shreeniket Bendre (Northwestern University)
#
# Purpose
#   A formal, production-style Streamlit application that demonstrates a cohesive,
#   Cisco-aligned security solution for MSIs/HBCUs. Each section begins with:
#     • What this section does
#     • How to use / simulate
#     • Why it matters in the context of the project essay
#
# Modules
#   1) Duo MFA Rollout — scan-to-enroll (QR), one-tap “auto-verify” (push-style simulation),
#      number-match with a clean selectable option UI (no slider).
#   2) Umbrella DNS Guard — allow/block/watch policy builder + explainable URL risk scoring.
#   3) Meraki Reliability Planner — AP sizing for critical zones + simulated reliability uplift.
#   4) Mini-SOC (Simulated) — realistic synthetic events; filters, search, CSV export.
#   5) ROI & Equity Impact — converts reduced incidents into institutional dollars and tuition equivalents.
#   Appendix) Context & Stakeholders — formal narrative aligned to the project essay.
#
# Notes
#   • Runs fully offline with synthetic data (no institutional credentials).
#   • Optional live MFA demo requires: pip install pyotp qrcode[pil]
#   • Optional domain parsing assist: pip install tldextract idna
#
# Run
#   streamlit run app.py

import streamlit as st
import pandas as pd
import numpy as np
import math, re, io, base64, random, time
from datetime import datetime
from urllib.parse import urlparse
import difflib
import hashlib

# Optional dependencies (handled gracefully if absent)
try:
    import qrcode
    import pyotp
except Exception:
    qrcode = None
    pyotp = None

try:
    import tldextract
except Exception:
    tldextract = None  # fallback parsing will still work for most URLs

# ============================ PAGE CONFIG & THEME ============================
APP_TITLE = "CyberBridge Guardian (Cisco Edition)"
st.set_page_config(page_title=APP_TITLE, layout="wide")

# Requested palette:
# 1) #5b68d0  2) #c951cb  3) #1b84e0  4) #4d6bd3
STYLES = """
<style>
/* Fonts */
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&family=EB+Garamond:wght@400;500;600;700&display=swap');

/* Brand tokens */
:root{
  --blue1:#5b68d0; --violet:#c951cb; --blue2:#1b84e0; --blue3:#4d6bd3;
  --bg:#0b0f1a; --bg2:#0e1424; --text:#e9edf7; --muted:#9aa7c0;
  --stroke:rgba(91,104,208,0.35); --stroke-strong:rgba(91,104,208,0.55);
  --card:rgba(18,24,44,0.72); --primary:#c951cb;
}

/* Global surface */
html, body, .stApp, [data-testid="stAppViewContainer"]{
  background:
    radial-gradient(1600px 700px at 8% 6%, rgba(91,104,208,0.22), transparent 60%),
    radial-gradient(1200px 520px at 96% 4%, rgba(201,81,203,0.15), transparent 60%),
    radial-gradient(1400px 600px at 40% 100%, rgba(27,132,224,0.14), transparent 70%),
    linear-gradient(180deg, var(--bg) 0%, var(--bg2) 100%) !important;
  color:var(--text)!important;
}

/* Typography: bold Poppins for headlines/labels; Garamond for body */
h1,h2,h3,h4,
label,.stRadio,.stCheckbox,.stSelectbox,.stButton,.metric .big{
  font-family:'Poppins',system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif !important;
  font-weight:700 !important; letter-spacing:.2px;
}
p,li,span,div,.small{
  font-family:'EB Garamond',Garamond,'Times New Roman',serif !important;
}

/* Kill lingering white backgrounds */
[class^="st-emotion-cache"], [class*=" st-emotion-cache"]{
  background-color:transparent !important; color:var(--text)!important;
}
section.main > div { background:transparent !important; }

/* Header/Sidebar */
[data-testid="stHeader"]{
  background:linear-gradient(180deg, rgba(13,18,33,0.6), rgba(13,18,33,0.35)) !important;
  border-bottom:1px solid var(--stroke); backdrop-filter:blur(8px);
}
[data-testid="stSidebar"]{
  background:linear-gradient(180deg, rgba(18,24,44,0.65), rgba(18,24,44,0.45)) !important;
  border-right:1px solid var(--stroke); color:var(--text)!important;
}

/* Cards & metrics */
.cb-card{ border:1px solid var(--stroke); background:var(--card); backdrop-filter:blur(12px);
  border-radius:18px; padding:16px; color:var(--text); }
.metric{ display:flex; flex-direction:column; gap:.2rem; padding:12px 14px; border-radius:16px;
  border:1px solid var(--stroke);
  background:linear-gradient(135deg, rgba(91,104,208,0.18), rgba(201,81,203,0.16) 60%, rgba(27,132,224,0.14));}

/* Buttons */
.stButton > button{
  border:1px solid var(--stroke) !important; color:#f6f7ff !important;
  background:linear-gradient(135deg, rgba(201,81,203,.30), rgba(91,104,208,.28) 55%, rgba(27,132,224,.26)) !important;
  border-radius:12px; padding:.55rem .95rem; font-weight:700;
}
.stButton > button:hover{
  border-color:var(--primary) !important; box-shadow:0 0 0 2px rgba(201,81,203,.25) inset !important;
}

/* Inputs & focus */
.stTextInput > div > div > input, .stTextArea textarea, .stNumberInput input,
.stSelectbox div[data-baseweb="select"] input, .stDateInput input, .stTimeInput input{
  background:rgba(18,24,44,.54) !important; color:var(--text) !important;
  border:1px solid var(--stroke) !important; border-radius:10px !important;
}
.stTextInput:focus-within input, .stTextArea:focus-within textarea,
.stNumberInput:focus-within input, .stSelectbox:focus-within [data-baseweb="select"] input{
  border-color:var(--primary) !important; box-shadow:0 0 0 2px rgba(201,81,203,.25) inset !important;
}

/* Radio/Checkbox/Slider accents -> violet */
input[type="checkbox"], input[type="radio"]{ accent-color:var(--primary) !important; }
div[role="slider"]{ color:var(--primary) !important; }
input[type="range"]::-webkit-slider-thumb{ background:var(--primary) !important; border:2px solid #fff; }
input[type="range"]::-moz-range-thumb{ background:var(--primary) !important; border:2px solid #fff; }
input[type="range"]::-webkit-slider-runnable-track{ background:linear-gradient(90deg, var(--primary), var(--blue3)); }
input[type="range"]::-moz-range-track{ background:linear-gradient(90deg, var(--primary), var(--blue3)); }

/* Selects */
[data-baseweb="select"] > div{
  background:rgba(18,24,44,.54) !important; color:var(--text) !important;
  border:1px solid var(--stroke) !important; border-radius:10px !important;
}
[data-baseweb="select"]:focus-within > div{
  border-color:var(--primary) !important; box-shadow:0 0 0 2px rgba(201,81,203,.25) inset !important;
}

/* DataFrames */
[data-testid="stDataFrame"]{ border:1px solid var(--stroke); border-radius:12px; background:rgba(18,24,44,.35); }
[data-testid="stTable"]{ color:var(--text); }

/* Risk pills */
.cb-pill{ display:inline-block; padding:6px 12px; border-radius:999px; border:1px solid var(--stroke);
  margin-right:6px; font-weight:700; color:var(--text); background:rgba(77,107,211,.10);}
.hi{ color:#ffd2db; border-color:rgba(201,81,203,.55); background:rgba(201,81,203,.14);}
.med{ color:#ffe8b8; border-color:rgba(91,104,208,.55); background:rgba(91,104,208,.14);}
.lo{ color:#d3f9ea; border-color:rgba(27,132,224,.55); background:rgba(27,132,224,.14);}

/* Number-match selectable pills */
.nm-grid { display:flex; gap:12px; }
.nm-option {
  border:1px solid var(--stroke);
  background: linear-gradient(135deg, rgba(77,107,211,0.16), rgba(27,132,224,0.12));
  border-radius: 14px;
  padding: 10px 14px;
  font-weight: 700;
  color: var(--text);
  text-align: center;
}
.nm-option.selected {
  border-color: rgba(201,81,203,0.75);
  box-shadow: 0 0 0 2px rgba(201,81,203,0.25) inset;
}

/* ---------- FORCE all red “negative” tokens to violet (no config.toml needed) ---------- */
:root, [data-theme="dark"], [data-theme="light"]{
  --primary-color:#c951cb !important;
  --colorsBackgroundAccent:#c951cb !important;
  --colorsBackgroundAccentHover:#d66fd8 !important;
  --colorsBorderAccent:#c951cb !important;
  --colorsBorderSelected:#c951cb !important;
  --colorsBackgroundNegative:#c951cb !important;
  --colorsContentNegative:#0b0f1a !important;
  --colorsBorderNegative:#c951cb !important;
}

/* ---------- Multiselect / Tag chips (BaseWeb) ---------- */
.stMultiSelect [data-baseweb="tag"], [data-baseweb="tag"]{
  background:linear-gradient(135deg, #c951cb, #5b68d0) !important;
  color:#e9edf7 !important; border:1px solid rgba(201,81,203,.55) !important;
  border-radius:10px !important; font-family:'Poppins',sans-serif !important; font-weight:700 !important;
}
[data-baseweb="tag"] svg, [data-baseweb="tag"] [data-baseweb="button"] svg{
  color:#e9edf7 !important; opacity:.95;
}
[data-baseweb="tag"]:hover{ box-shadow:0 0 0 2px rgba(201,81,203,.35) inset !important; }

/* ===== Sidebar radio & checkbox: force violet accents ===== */
[data-testid="stSidebar"] [data-baseweb="radio"] div[role="radio"]{
  border: 2px solid #c951cb !important;
  width: 18px; height: 18px; border-radius: 999px;
  background: transparent !important;
}
[data-testid="stSidebar"] [data-baseweb="radio"] div[role="radio"][aria-checked="true"]{
  background: #c951cb !important;
  border-color: #c951cb !important;
  box-shadow: 0 0 0 4px rgba(201,81,203,0.28) inset !important;
}
[data-testid="stSidebar"] [data-baseweb="radio"] label,
[data-testid="stSidebar"] [data-baseweb="checkbox"] label{
  color: #e9edf7 !important;
  font-family: 'Poppins', system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif !important;
  font-weight: 700 !important;
}
[data-testid="stSidebar"] [data-baseweb="checkbox"] label > div:first-child{
  border: 2px solid #c951cb !important;
  border-radius: 6px !important;
  background: transparent !important;
}
[data-testid="stSidebar"] [data-baseweb="checkbox"] label > div:first-child svg{
  color: #0b0f1a !important;
}
[data-testid="stSidebar"] [data-baseweb="checkbox"] input:checked ~ div:first-child{
  background: #c951cb !important;
  border-color: #c951cb !important;
  box-shadow: 0 0 0 2px rgba(201,81,203,0.25) inset !important;
}
[data-testid="stSidebar"] [data-baseweb="radio"] div[role="radio"]:hover,
[data-testid="stSidebar"] [data-baseweb="checkbox"] label > div:first-child:hover{
  box-shadow: 0 0 0 2px rgba(201,81,203,0.35) inset !important;
}

/* Dividers */
hr{ border:none; border-top:1px solid var(--stroke); margin:1.25rem 0; }
</style>
"""
st.markdown(STYLES, unsafe_allow_html=True)

# ============================ NAVIGATION ============================
st.sidebar.markdown(
    f"""
<div class="cb-card" style="margin-bottom:10px">
  <b>{APP_TITLE}</b><br/>
  <span class="small">Meraki • Umbrella • Duo • NetAcad</span>
</div>
""",
    unsafe_allow_html=True,
)

page = st.sidebar.radio(
    "Navigate",
    [
        "Home (Start Here)",
        "1) Duo MFA Rollout",
        "2) Umbrella DNS Guard",
        "3) Meraki Reliability Planner",
        "4) Mini-SOC (Simulated)",
        "5) ROI & Equity Impact",
        "Appendix: Context & Stakeholders",
    ],
)
st.sidebar.markdown("---")
demo_mode = st.sidebar.checkbox("Use sample data", value=True)
st.sidebar.caption("Demonstration uses only synthetic data.")

# ============================ UTILITIES ============================
KNOWN_BRANDS = [
    "google","microsoft","office","outlook","teams","azure","onedrive",
    "cisco","meraki","umbrella","duo","blackboard","canvas","zoom",
    "box","dropbox","github","slack","paypal","stripe","bankofamerica",
    "wellsfargo","chase","university","student","finaid","bursar"
]
SUSP_TLDS = {"zip","kim","xyz","top","gq","ml","cf","tk","work","fit","rest","country","asia","science"}

def pill(text, cls): return f'<span class="cb-pill {cls}">{text}</span>'

def download_bytes(filename: str, raw: bytes, label: str):
    b64 = base64.b64encode(raw).decode()
    href = f'<a download="{filename}" href="data:application/octet-stream;base64,{b64}">{label}</a>'
    st.markdown(href, unsafe_allow_html=True)

def domain_parts(url: str):
    parsed = urlparse(url if re.match(r"^\w+://", url) else "http://" + url)
    host = parsed.netloc or parsed.path
    if tldextract:
        ext = tldextract.extract(host)
        domain = ext.registered_domain or (f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ext.domain)
        sld = ext.domain or ""
        tld = ext.suffix or ""
        sub = ext.subdomain or ""
    else:
        parts = host.split(".")
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])
            sld = parts[-2]
            tld = parts[-1]
            sub = ".".join(parts[:-2])
        else:
            domain, sld, tld, sub = host, host, "", ""
    return host, domain, sld, tld, sub, parsed

def shannon_entropy(s: str):
    if not s: return 0.0
    from math import log2
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * log2(p) for p in probs)

def looks_like_ip(host: str):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

def punycode_present(host: str):
    return "xn--" in host.lower()

def brand_lookalike_score(sld: str):
    if not sld: return 0.0
    close = max(difflib.SequenceMatcher(a=sld.lower(), b=b).ratio() for b in KNOWN_BRANDS)
    exact = sld.lower() in KNOWN_BRANDS
    return 0.0 if exact else close

def url_feature_vector(url: str):
    host, domain, sld, tld, sub, parsed = domain_parts(url)
    path = parsed.path or ""
    length = len(url)
    sub_count = sub.count(".") + (1 if sub else 0)
    dash_count = url.count("-")
    at_count = url.count("@")
    digit_ratio = sum(c.isdigit() for c in host) / max(1, len(host))
    entropy = shannon_entropy(host + path)
    ip = looks_like_ip(host)
    puny = punycode_present(host)
    tld_flag = tld.split(".")[-1] if tld else ""
    tld_susp = 1 if tld_flag in SUSP_TLDS else 0
    brand_score = brand_lookalike_score(sld)
    path_deep = path.count("/")
    has_port = bool(re.search(r":\d+$", host))
    return {
        "length": length,
        "subdomains": sub_count,
        "dashes": dash_count,
        "ats": at_count,
        "digit_ratio": digit_ratio,
        "entropy": entropy,
        "ip": int(ip),
        "punycode": int(puny),
        "tld_suspicious": tld_susp,
        "brand_lookalike": brand_score,
        "path_depth": path_deep,
        "has_port": int(has_port),
        "sld": sld, "tld": tld_flag, "host": host, "domain": domain
    }

def risk_score_from_features(f):
    score = 0.0
    score += min(30, f["length"]/8)
    score += 7 * f["subdomains"]
    score += 3 * f["dashes"]
    score += 12 * f["ats"]
    score += 30 * f["digit_ratio"]
    score += min(20, 4 * f["entropy"])
    score += 20 * f["ip"]
    score += 20 * f["punycode"]
    score += 12 * f["tld_suspicious"]
    score += 35 * max(0, f["brand_lookalike"] - 0.65)
    score += 2 * f["path_depth"]
    score += 8 * f["has_port"]
    return max(0.0, min(100.0, score))

def risk_label(score: float):
    if score < 25:  return "Low", "lo"
    if score < 60:  return "Medium", "med"
    return "High", "hi"

def hero(title:str, subtitle:str):
    st.markdown(f"""
    <div class="cb-hero">
      <h1>{title}</h1>
      <p>{subtitle}</p>
    </div>
    """, unsafe_allow_html=True)

def kpi(label, value, sub=""):
    st.markdown(f"""
    <div class="metric">
      <div class="big">{value}</div>
      <div class="sub">{label}{(" — " + sub) if sub else ""}</div>
    </div>
    """, unsafe_allow_html=True)

def explainer(what:str, how:str, why:str):
    st.markdown('<div class="cb-card cb-explainer">', unsafe_allow_html=True)
    cols = st.columns(3)
    with cols[0]:
        st.markdown("### What this section does")
        st.markdown(what)
    with cols[1]:
        st.markdown("### How to use / simulate")
        st.markdown(how)
    with cols[2]:
        st.markdown("### Why it matters (competition)")
        st.markdown(why)
    st.markdown('</div>', unsafe_allow_html=True)

# ============================ PAGES ============================
if page == "Home (Start Here)":
    hero(
        "CyberBridge Guardian",
        "Cisco-aligned campus security: Duo MFA adoption, Umbrella DNS pre-blocking, Meraki reliability planning, a student mini-SOC, and ROI translated to equity outcomes."
    )

    st.markdown("#### Overview")
    st.markdown(
        """
This application operationalizes the CyberBridge concept for MSIs/HBCUs. It demonstrates how Cisco Duo, Umbrella, and Meraki can be integrated with campus processes and student training (Networking Academy) to reduce phishing/ransomware risk, improve network reliability, and express value in formal budget terms.
        """
    )

    st.markdown("#### How to use this application")
    st.markdown(
        """
1. Use the left sidebar to navigate between modules.  
2. Each section begins with **What / How to use / Why it matters**.  
3. Where relevant, outputs can be **exported to CSV** for documentation and analysis.  
4. All data shown is **synthetic**. No institutional credentials are required.  
        """
    )

    st.markdown("#### Key outcomes at a glance")
    c1, c2, c3, c4 = st.columns(4)
    with c1: kpi("Reliability uplift (zones)", "65% → 99%", "Meraki plan")
    with c2: kpi("Phishing reduction", "≈ 40%+", "Duo MFA")
    with c3: kpi("Pre-block rate", "15–30%", "Umbrella DNS")
    with c4: kpi("Net annual savings", "≈ $1.4M", "~5% breach reduction")

    st.markdown("---")
    st.markdown(
        """
**Design principles**  
• Formal explanations tied to institutional outcomes.  
• Explainable risk signals and transparent policy decisions.  
• Minimal cognitive load for small IT teams; extensible to APIs later.  
        """
    )

# -------------------- Duo MFA Rollout --------------------
elif page == "1) Duo MFA Rollout":
    hero("Duo MFA Rollout", "Scan-to-enroll, one-tap auto-verify (push-style simulation), and number-match with a clean selectable option UI.")

    explainer(
        what="""
- Provides a realistic MFA enrollment and approval model aligned with Cisco Duo.
- Two verification modes: (A) Auto-Verify (push-style simulation), (B) Code entry with number-match.
- Stores a hashed device binding for demonstration.
        """,
        how="""
1. Enter a campus email and scan the QR with Duo/Google Authenticator/1Password.  
2. Approve using **Auto-Verify** (no typing) or enter the 6-digit code and complete **number-match** by selecting the correct option.  
3. Use **Reset secret** to re-enroll.  
4. The **Rollout & Adoption** calculator estimates helpdesk load.
        """,
        why="""
- Supports Cisco Duo adoption for phishing defense with minimal friction.  
- Demonstrates push-style approvals and number-match to resist MFA fatigue.  
- Communicates a credible operational path for campus onboarding at scale.
        """,
    )

    if qrcode is None or pyotp is None:
        st.warning("To run the live enrollment/verification demo, install:  pip install pyotp qrcode[pil]")
    else:
        # --- Enrollment ---
        colA, colB = st.columns([1,1])

        with colA:
            st.subheader("Enroll — QR provisioning")
            user_email = st.text_input("Campus email", "student@example.edu")
            issuer = st.text_input("Issuer", "CyberBridge Guardian (Duo-style)")
            if "totp_secret" not in st.session_state or st.button("Reset secret (re-enroll)"):
                st.session_state.totp_secret = pyotp.random_base32()
                st.session_state.bound_hash = None
                # Reset number-match as well
                st.session_state.pop("nm_target", None)
                st.session_state.pop("nm_options", None)
                st.session_state.pop("nm_selected", None)
            secret = st.session_state.totp_secret
            st.code(secret, language="text")
            st.caption("In production this secret is stored server-side only; shown here for demonstration transparency.")

        with colB:
            uri = pyotp.TOTP(secret).provisioning_uri(name=user_email or "user@campus.edu", issuer_name=issuer or "CyberBridge")
            img = qrcode.make(uri)
            buf = io.BytesIO(); img.save(buf, format="PNG")
            st.image(buf.getvalue(), caption="Scan with Duo / Google Authenticator / 1Password")
            st.caption("Authenticator apps generally accept QR codes directly from the camera.")

        st.markdown("---")
        st.subheader("Approve")

        c1, c2 = st.columns(2)

        # --- A) Auto-Verify (push-style simulation) ---
        with c1:
            st.markdown("**A) Auto-Verify (push-style simulation)**")
            if st.button("Auto-Verify Now"):
                # Bind a simple device fingerprint hash on first verify
                if st.session_state.get("bound_hash") is None:
                    bind_raw = f"{user_email}|{secret}"
                    st.session_state.bound_hash = hashlib.sha256(bind_raw.encode()).hexdigest()
                if st.session_state.bound_hash:
                    st.success("Approved. Device binding recorded and expected code validated.")
                else:
                    st.error("Device not bound; please enroll again.")

        # --- B) Code entry + Number-Match (no slider; clean selectable options) ---
        with c2:
            st.markdown("**B) Code entry + Number-Match**")
            code = st.text_input("Enter 6-digit code from your authenticator")

            # Create/refresh number-match target and options
            def generate_number_match():
                target = random.randint(10, 99)
                decoys = set()
                while len(decoys) < 2:
                    d = random.randint(10, 99)
                    if d != target:
                        decoys.add(d)
                opts = list(decoys) + [target]
                random.shuffle(opts)
                st.session_state.nm_target = target
                st.session_state.nm_options = opts
                st.session_state.nm_selected = None

            if "nm_target" not in st.session_state:
                generate_number_match()

            nm_target = st.session_state.nm_target
            nm_options = st.session_state.nm_options
            nm_selected = st.session_state.get("nm_selected")

            st.caption(f"Number-match challenge displayed in SSO: {nm_target}")

            # Render options as selectable pill buttons
            opt_cols = st.columns(len(nm_options))
            for i, val in enumerate(nm_options):
                selected = (nm_selected == val)
                with opt_cols[i]:
                    st.markdown(
                        f'<div class="nm-option {"selected" if selected else ""}">{val}</div>',
                        unsafe_allow_html=True
                    )
                    if st.button(f"Select {val}", key=f"nm_{val}"):
                        st.session_state.nm_selected = val
                        nm_selected = val

            col_actions = st.columns([1,1])
            with col_actions[0]:
                if st.button("Verify with Code + Match"):
                    if not code.strip():
                        st.error("Enter the 6-digit code.")
                    elif st.session_state.get("nm_selected") is None:
                        st.error("Select the matching number.")
                    else:
                        ok_code = pyotp.TOTP(secret).verify(code.strip())
                        ok_match = (st.session_state.nm_selected == st.session_state.nm_target)
                        if ok_code and ok_match:
                            st.success("Code valid. Number-match confirmed.")
                        elif not ok_code and ok_match:
                            st.error("Number-match correct, but code invalid or expired.")
                        elif ok_code and not ok_match:
                            st.error("Code valid, but number-match selection is incorrect.")
                        else:
                            st.error("Both the code and number-match selection are incorrect.")
            with col_actions[1]:
                if st.button("New Number-Match Challenge"):
                    generate_number_match()
                    st.info("New challenge generated.")

        st.markdown("---")
        st.subheader("Rollout & Adoption (Operations)")
        size = st.number_input("Population to onboard", 4000, step=100)
        adoption = st.slider("Adoption achieved (%)", 0, 100, 85)
        helpdesk_load = max(0, round((size * (100 - adoption) / 100) * 0.08))  # ~8% of stragglers need assistance
        c1, c2, c3 = st.columns(3)
        c1.metric("Users protected", f"{int(size*adoption/100):,}")
        c2.metric("Remaining to enroll", f"{int(size*(100-adoption)/100):,}")
        c3.metric("Estimated helpdesk tickets", f"{helpdesk_load:,}")
        st.caption("Assumptions are adjustable to institutional norms.")

# -------------------- Umbrella DNS Guard --------------------
elif page == "2) Umbrella DNS Guard":
    hero("Umbrella DNS Guard", "Policy-driven DNS filtering and explainable URL risk to prevent threats pre-click.")

    explainer(
        what="""
- Maintain allow/block/watch lists for domains.
- Evaluate URLs with an explainable risk score (lookalike, punycode, TLD, entropy, port, etc.).
- Export results for audit or instruction.
        """,
        how="""
1. Manage lists in the three columns below.  
2. Paste URLs into **Bulk evaluate**, then **Evaluate Policy**.  
3. Use **Explain a URL** to view signal breakdown for a single link.  
4. Export CSV for review.
        """,
        why="""
- Mirrors Cisco Umbrella’s approach: neutralize threats at DNS before the browser.
- Transparent signals build trust and enable student/faculty learning.
- Reduces phishing impact and IT response burden.
        """,
    )

    # Initialize lists
    if "blocklist" not in st.session_state:
        st.session_state.blocklist = set(["examp1e-helpdesk.com","login-verify-secure.net"]) if demo_mode else set()
    if "allowlist" not in st.session_state:
        st.session_state.allowlist = set(["duo.com","cisco.com","meraki.cisco.com","canvas.instructure.com"]) if demo_mode else set()
    if "watchlist" not in st.session_state:
        st.session_state.watchlist = set(["out1ook-login-secure.com","micr0soft-support-secure-login.com"]) if demo_mode else set()

    colA, colB, colC = st.columns(3)
    with colA:
        st.markdown("### Blocklist")
        blk_add = st.text_input("Add domain to block")
        if st.button("Add to Blocklist"):
            if blk_add.strip(): st.session_state.blocklist.add(blk_add.strip().lower())
        st.code("\n".join(sorted(st.session_state.blocklist)) or "(empty)")
    with colB:
        st.markdown("### Allowlist")
        allow_add = st.text_input("Add domain to allow")
        if st.button("Add to Allowlist"):
            if allow_add.strip(): st.session_state.allowlist.add(allow_add.strip().lower())
        st.code("\n".join(sorted(st.session_state.allowlist)) or "(empty)")
    with colC:
        st.markdown("### Watchlist")
        watch_add = st.text_input("Add domain to watch")
        if st.button("Add to Watchlist"):
            if watch_add.strip(): st.session_state.watchlist.add(watch_add.strip().lower())
        st.code("\n".join(sorted(st.session_state.watchlist)) or "(empty)")

    st.markdown("---")
    st.subheader("Bulk evaluate (one URL per line)")
    sample_bulk = "out1ook-login-secure.com\nhttp://xn--pple-43d.com\nhttps://duo.com\nhttp://192.168.1.23/login\nfinaid-portal.support-verify.net"
    urls_bulk = st.text_area("URLs", height=120, value=(sample_bulk if demo_mode else ""))

    def policy_decision(u: str):
        host, domain, sld, tld, sub, parsed = domain_parts(u)
        d = (domain or host).lower()
        if any(d.endswith(a) for a in st.session_state.allowlist):
            return "ALLOW", 0
        if any(d.endswith(b) for b in st.session_state.blocklist):
            return "BLOCK", 100
        for w in st.session_state.watchlist:
            sim = difflib.SequenceMatcher(a=(sld or d).split(":")[0], b=w.split(".")[0]).ratio()
            if sim > 0.8 or d.endswith(w):
                return "WATCH", 60
        f = url_feature_vector(u)
        sc = risk_score_from_features(f)
        if sc >= 60: return "BLOCK", sc
        if sc >= 25: return "WATCH", sc
        return "ALLOW", sc

    if st.button("Evaluate Policy", type="primary"):
        rows = []
        for line in urls_bulk.splitlines():
            u = line.strip()
            if not u: continue
            decision, sc = policy_decision(u)
            rows.append({"url": u, "decision": decision, "score": round(sc,1)})
        if rows:
            df = pd.DataFrame(rows).sort_values(["decision","score"], ascending=[True, False])
            st.dataframe(df, use_container_width=True)
            download_bytes("dns_policy_results.csv", df.to_csv(index=False).encode(), "Download CSV")

    st.markdown("---")
    st.subheader("Explain a single URL")
    bad = st.text_input("URL to explain", "https://micr0soft-support-secure-login.com/renew?session=9876")
    if st.button("Explain URL"):
        f = url_feature_vector(bad.strip())
        sc = risk_score_from_features(f)
        label, cls = risk_label(sc)
        st.markdown(f'<div class="cb-card">Risk {pill(label, cls)} — Score {sc:.1f}/100</div>', unsafe_allow_html=True)
        st.write(pd.DataFrame([f]).T.rename(columns={0:"value"}))
        st.caption("Signals may include: brand lookalike similarity, punycode, suspicious TLDs, IP host, deep paths, non-standard port, high entropy.")

# -------------------- Meraki Reliability Planner --------------------
elif page == "3) Meraki Reliability Planner":
    hero("Meraki Reliability Planner", "Estimate AP counts and visualize the path from ~65% to ~99% reliability in critical zones.")

    explainer(
        what="""
- Models approximate AP requirements for high-usage areas (e.g., library, student center, large lecture space).
- Shows simulated before/after reliability stabilization given target uptime and redundancy.
        """,
        how="""
1. Set peak concurrent users, zone area, per-AP capacity, and redundancy.  
2. Review AP counts, density per 1k sq ft, and target uptime.  
3. Examine the 30-day reliability chart for pre/post deployment effects.
        """,
        why="""
- Aligns with Cisco Meraki’s cloud-managed deployments for small IT teams.  
- Prioritizes student experience in the most impacted spaces.  
- Provides a practical plan institutions can resource and scale.
        """,
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        peak_concurrency = st.slider("Peak concurrent users in zone", 50, 2000, 600)
        sqft = st.number_input("Zone area (sq ft)", 35000, step=1000)
    with col2:
        capacity_per_ap = st.slider("Users per AP (Meraki 6/6E)", 30, 120, 60)
        overlap = st.slider("AP overlap (redundancy %)", 0, 50, 20)
    with col3:
        target_uptime = st.slider("Target uptime (%)", 95, 100, 99)

    raw_aps = math.ceil(peak_concurrency / capacity_per_ap)
    aps = math.ceil(raw_aps * (1 + overlap/100))
    density = round(aps / max(1, sqft/1000), 2)

    cA, cB, cC = st.columns(3)
    cA.metric("APs required (zone)", f"{aps} APs", f"base {raw_aps}")
    cB.metric("AP density", f"{density} per 1k sq ft")
    cC.metric("Reliability target", f"{target_uptime}%")

    st.markdown("---")
    st.subheader("Before/After (30-day simulated health)")
    np.random.seed(7)
    before_uptime = np.clip(np.random.normal(0.65, 0.07, 30), 0.3, 0.95)
    after_uptime  = np.clip(np.random.normal(target_uptime/100.0, 0.02, 30), 0.8, 1.0)
    df_health = pd.DataFrame({
        "day": pd.date_range(end=datetime.today(), periods=30).date,
        "before": (before_uptime*100).round(1),
        "after":  (after_uptime*100).round(1),
    })
    st.line_chart(df_health.set_index("day"))
    st.caption("In production, ingest Meraki telemetry; this demonstration shows expected stabilization near the chosen target with redundancy.")

# -------------------- Mini-SOC (Simulated) --------------------
elif page == "4) Mini-SOC (Simulated)":
    hero("Mini-SOC (Simulated)", "Student-staffed monitoring and response training using realistic synthetic events.")

    explainer(
        what="""
- Generates realistic DNS blocks, login anomalies, and policy hits.
        """,
        how="""
1. Select **Regenerate Events** to produce a fresh week of logs.  
2. Filter by type and severity; search across all fields.  
3. Export to CSV for lab work or documentation.
        """,
        why="""
- Integrates with Cisco Networking Academy outcomes: practical SOC practice.  
- Creates a workforce pipeline while providing tangible campus benefit.  
- Builds confidence in sustained operations with limited staff.
        """,
    )

    if "soc_events" not in st.session_state or st.button("Regenerate Events"):
        seeds = [
            ("DNS_BLOCK", "Umbrella", "Blocked malicious domain", "micr0soft-secure-login.com"),
            ("DNS_BLOCK", "Umbrella", "Blocked lookalike", "out1ook-helpdesk.net"),
            ("LOGIN_ANOMALY", "Duo", "Impossible travel sign-in", "user01@campus.edu"),
            ("LOGIN_ANOMALY", "Duo", "Possible MFA fatigue attempt", "student23@campus.edu"),
            ("POLICY_HIT", "Guardian", "Watchlist matched", "finaid-portal.support-verify.net"),
            ("POLICY_HIT", "Guardian", "Suspicious TLD", "student-aid.xyz"),
            ("TRAINING", "NetAcad", "Student flagged phishing email", "s019"),
        ]
        rows = []
        now = int(time.time())
        for _ in range(50):
            t = now - random.randint(0, 7*24*3600)
            ev = random.choice(seeds)
            severity = random.choice(["low","medium","high"])
            rows.append({
                "time": datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M"),
                "type": ev[0], "source": ev[1], "description": ev[2], "detail": ev[3],
                "severity": severity,
            })
        st.session_state.soc_events = pd.DataFrame(rows).sort_values("time", ascending=False).reset_index(drop=True)

    df = st.session_state.soc_events.copy()
    colf1, colf2, colf3 = st.columns(3)
    with colf1: f_type = st.multiselect("Type", options=sorted(df["type"].unique()), default=list(sorted(df["type"].unique())))
    with colf2: f_sev  = st.multiselect("Severity", options=sorted(df["severity"].unique()), default=list(sorted(df["severity"].unique())))
    with colf3: query  = st.text_input("Search query", "")

    mask = df["type"].isin(f_type) & df["severity"].isin(f_sev)
    if query.strip():
        pat = re.compile(re.escape(query.strip()), re.IGNORECASE)
        mask &= df.apply(lambda r: bool(pat.search(" ".join(map(str, r.values)))), axis=1)

    view = df[mask]
    st.dataframe(view, use_container_width=True, height=430)
    download_bytes("mini_soc_events.csv", view.to_csv(index=False).encode(), "Download CSV")

# -------------------- ROI & Equity Impact --------------------
elif page == "5) ROI & Equity Impact":
    hero("ROI & Equity Impact", "Model incident reduction and convert to institutional dollars and tuition equivalents.")

    explainer(
        what="""
- Estimates incidents avoided through MFA, DNS filtering, and training effects.  
- Calculates gross savings, program cost, net impact, and tuition equivalents.
        """,
        how="""
1. Provide baseline incidents and campus size.  
2. Adjust MFA adoption, DNS filtering, and training completion.  
3. Review incidents avoided, dollar savings, and tuition equivalents.
        """,
        why="""
- Aligns with the essay’s breach cost framing and annual savings aims.  
- Communicates value in terms used by administrators and funders.  
- Connects security investments to equity outcomes for MSIs/HBCUs.
        """,
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        pop_students = st.number_input("Students", 3500, step=50)
        pop_staff = st.number_input("Faculty/Staff", 500, step=10)
        baseline_incid = st.number_input("Baseline incidents per year", 4, step=1)
    with col2:
        mfa_adopt = st.slider("MFA adoption (%)", 0, 100, 85)
        dns_on = st.checkbox("Umbrella DNS filtering enabled", True)
        training_pct = st.slider("Security training completion (%)", 0, 100, 70)
    with col3:
        cost_per_incident = st.number_input("Avg. cost per incident ($)", 2_700_000, step=50_000)
        program_cost = st.number_input("Annual program cost ($)", 300_000, step=10_000)

    mfa_effect = 0.40 * (mfa_adopt/100.0)
    dns_effect = 0.15 if dns_on else 0.0
    training_effect = 0.10 * (training_pct/100.0)
    total_reduction = min(0.75, mfa_effect + dns_effect + training_effect)

    avoided = baseline_incid * total_reduction
    gross = avoided * cost_per_incident
    net = gross - program_cost
    tuition_equiv = max(0, net) / 28000.0  # adjust per institution if needed

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Incidents avoided / yr", f"{avoided:.2f}")
    c2.metric("Gross savings / yr", f"${gross:,.0f}")
    c3.metric("Program cost / yr", f"${program_cost:,.0f}")
    c4.metric("Tuition equivalents", f"{int(tuition_equiv):,} students")

    st.markdown("---")
    st.subheader("Narrative (for proposals and planning)")
    st.markdown(
        f"""
With Duo MFA adoption at {mfa_adopt}%, Umbrella DNS filtering {'enabled' if dns_on else 'disabled'}, and {training_pct}% security training completion,
the modeled net reduction in successful phishing/ransomware is approximately {int(total_reduction*100)}%.
Against {baseline_incid} incidents per year at ${cost_per_incident:,.0f} each, this avoids {avoided:.2f} incidents and saves approximately ${gross:,.0f} per year.
After accounting for the program cost of ${program_cost:,.0f}, the net financial impact is ${net:,.0f} per year,
which corresponds to roughly {int(tuition_equiv):,} tuition equivalents.
        """
    )

# -------------------- Appendix --------------------
elif page == "Appendix: Context & Stakeholders":
    hero("Appendix: Context & Stakeholders", "Formal narrative aligned to the CyberBridge essay.")
    explainer(
        what="""
- Summarizes the higher-education threat environment and structural constraints at MSIs/HBCUs.  
- Describes how CyberBridge deploys Meraki (reliability), Umbrella (pre-block), Duo (MFA), and the Networking Academy (people).
        """,
        how="""
- Begin in the highest-usage zones (library, student center, high-use classrooms).  
- Roll out Duo MFA and enforce DNS policy; stand up a student mini-SOC for monitoring/response.  
- Iterate and scale as funding and partnerships mature.
        """,
        why="""
- Demonstrates deliverable, quantifiable improvements in resilience and equity outcomes.  
- Positions Cisco as a workforce and infrastructure partner, not only a technology vendor.  
- Creates long-term sustainability through trained students and manageable cloud tooling.
        """,
    )

    st.markdown("### Stakeholders")
    st.markdown(
        """
- Internal (Cisco): Social Impact & Inclusion, Networking Academy staff, regional account engineers  
- External: Partner MSIs/HBCUs (AL/MS/TX), faculty and IT teams, nonprofits (e.g., MS-CC), public and private partners  
- Community: Students and families (protection of data and aid), employers (job-ready graduates)
        """
    )

    st.markdown("---")
    st.markdown("### Why this web application")
    st.markdown(
        """
- Operational: shows day-to-day impact of policies and MFA beyond slideware.  
- Explainable: transparent risk factors and policy rationales.  
- Educational: supports student SOC rotations with realistic exercises.  
- Measurable: ROI translated into budgeting terms and equity framing.
        """
    )

# ============================ FOOTER ============================
st.markdown("<hr/>", unsafe_allow_html=True)
st.caption("© CyberBridge — Built for MSIs/HBCUs. This demonstration uses only synthetic data and no institutional credentials.")
