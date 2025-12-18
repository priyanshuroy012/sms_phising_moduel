# app.py - Full Forensic Phishing Scanner (Online WHOIS + RDAP)
import streamlit as st
import joblib
import numpy as np
import re
import tldextract
import whois
import socket
from ipwhois import IPWhois
import datetime
import tempfile
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import requests
import os

# ----------------------
# CONFIG
# ----------------------
st.set_page_config(page_title="Full Forensic Phishing Scanner", page_icon="🛡️", layout="wide")

NOTEBOOK_PATH = "/mnt/data/Ai_project_phising_Email.ipynb"  # Your uploaded notebook (developer: provided path)

THREAT_KEYWORDS = [
    "password", "click here", "urgent", "verify", "confirm",
    "account suspended", "reset", "login", "verify identity",
    "bank", "otp", "payment", "refund", "unlock", "ssn", "id", "passport"
]

# ----------------------
# THEME SWITCH (toggle checkbox)
# ----------------------
toggle = st.sidebar.checkbox("🌙 Dark Mode", value=True)
THEME = "Dark" if toggle else "Light"

# CSS blocks for themes and animated cards
if THEME == "Dark":
    st.markdown("""
    <style>
    /* 1. Global Background & Text */
    body { background-color:#0b0b11 !important; color:#e6eef7; }
    [data-testid="stAppViewContainer"] { background: linear-gradient(145deg,#0b0b11,#0f0f16); }

    /* 2. Primary Results Card (POP) */
    .result-card {
        animation: fadeInCard 0.6s ease-out;
        background: linear-gradient(135deg,#13131f,#1e1e2c);
        border-radius:18px; /* Slightly rounder */
        padding:25px; /* More padding */
        box-shadow:0 0 30px rgba(0,220,255,0.15); /* Stronger glow */
        border:1px solid #00eaff33; /* Brighter border */
        margin-bottom: 20px;
    }
    @keyframes fadeInCard { 0%{opacity:0; transform:translateY(12px);} 100%{opacity:1; transform:translateY(0);} }
                * ⭐️ POP: Streamlit Headings (for st.markdown("## Heading")) ⭐️ */
    h1, h2, h3 {
        color: #b3e5fc; /* Lighter blue/cyan for contrast */
        text-shadow: 0 0 5px rgba(0, 220, 255, 0.2); /* Subtle glow */
        font-weight: 500; /* Medium weight for readability */
    }
    .big-title {
        font-size:42px; /* Bigger Title */
        text-align:center;
        color:#40c9ff;
        text-shadow:0 0 25px #00eaff;
        font-weight: 900;
        letter-spacing: 1px;
    }

    /* 3. Input Areas */
    textarea { background:#1a1a24; color:#d9d9e6; border-radius:12px; }

    /* 4. Button (POP) */
    div.stButton > button {
        background: linear-gradient(135deg,#0e82ff,#00d4ff);
        color:white;
        border-radius:12px; /* Rounder button */
        padding:15px 20px; /* Bigger button */
        font-weight:800;
        box-shadow:0 0 20px rgba(0,212,255,0.25); /* Stronger shadow */
        transition: all 0.3s ease;
    }
    div.stButton > button:hover {
        box-shadow:0 0 30px rgba(0,212,255,0.5); /* Intense hover glow */
    }

    /* 5. Highlight Key Metrics (using st.markdown later) */
    .score-high { font-size: 2.2em; color: #ff4b4b; font-weight: 900; }
    .score-low { font-size: 2.2em; color: #00ff88; font-weight: 900; }
                
    /* 5. DOWNLOAD BUTTON TEXT COLOR (MADE BLACK) */
    /* Target the stDownloadButton element. Streamlit download buttons use primary color for background, so we force black text. */
    [data-testid="stDownloadButton"] > button {
        color: black !important; /* Force black text for the download button */
        /* You might want to remove the shadow if it looks odd with black text */
        box-shadow: none !important; 
    }
                
    /* 6. Regular Markdown Text */
    p {
        color: #f0f8ff; /* Slightly brighter white for standard text */
    }

    /* 5. DOWNLOAD BUTTON STYLING (Made identical to Run Scan Button)  */
    [data-testid="stDownloadButton"] > button {
        background: linear-gradient(135deg,#0e82ff,#00d4ff); /* Gradient background */
        color: white !important; /* White text to match the main button */
        border-radius:12px;
        padding:15px 20px;
        font-weight: 600;
        box-shadow:0 0 20px rgba(0,212,255,0.25);
        transition: all 0.3s ease;
    }
    </style>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <style>
    /* === LIGHT THEME STYLES (Consistent Adaptation) === */
    /* 1. Global Background & Text */
    body { background-color:#ffffff !important; color:#111111; }
    [data-testid="stAppViewContainer"] { background: linear-gradient(145deg, #f0f4f8, #ffffff); }
    
    /* 2. Primary Results Card (POP) */
    .result-card {
        animation: fadeInCard 0.6s ease-out;
        background: #ffffff;
        border-radius:18px;
        padding:25px;
        box-shadow:0 4px 12px rgba(0, 0, 0, 0.1); /* Dark, soft shadow */
        border:1px solid #e3e6ea;
        margin-bottom: 20px;
    }
    @keyframes fadeInCard { 0%{opacity:0; transform:translateY(12px);} 100%{opacity:1; transform:translateY(0);} }
    
    /* Streamlit Headings */
    h1, h2, h3 {
        color: #0b6cff; /* Primary blue color */
        text-shadow: 1px 1px 3px rgba(0, 108, 255, 0.1); /* Subtle shadow */
        font-weight: 500;
    }

    /* Big Title (App Title) */
    .big-title {
        font-size:42px;
        text-align:center;
        color:#0b6cff;
        text-shadow: 0 4px 8px rgba(0, 108, 255, 0.2);
        font-weight: 700;
        letter-spacing: 1px;
    }

    /* 3. Input Areas */
    textarea { background:#f0f4f8; color:#111111; border-radius:12px; border: 1px solid #cccccc; }
    p { color: #333333; } /* Regular text color */

    /* 4. Regular st.button (POP) - Run Scan Button */
    div.stButton > button {
        background: linear-gradient(135deg,#0e82ff,#00d4ff);
        color:white; /* White text on dark button */
        border-radius:12px;
        padding:15px 20px;
        font-weight: 600;
        box-shadow:0 0 15px rgba(0,212,255,0.4);
        transition: all 0.3s ease;
    }
    div.stButton > button:hover {
        box-shadow:0 0 25px rgba(0,212,255,0.7);
    }
    
    /* 5. DOWNLOAD BUTTON STYLING (Identical to Run Scan Button) */
    [data-testid="stDownloadButton"] > button {
        background: linear-gradient(135deg,#0e82ff,#00d4ff);
        color: white !important;
        border-radius:12px;
        padding:15px 20px;
        font-weight: 600;
        box-shadow:0 0 15px rgba(0,212,255,0.4);
        transition: all 0.3s ease;
    }
    [data-testid="stDownloadButton"] > button:hover {
        box-shadow:0 0 25px rgba(0,212,255,0.7);
    }

    /* 6. Generic Metric Value Pop (Confidence) */
    .stMetricValue {
        font-size: 3.5em !important;
        color: #00897b !important; /* Dark teal for pop */
        text-shadow: none; 
    }
    .stMetricLabel {
        color: #555555;
        font-weight: 400;
    }
    
    /* 7. RISK SCORE SPECIFIC STYLING (The POPPIEST) */
    [data-testid="stMetricValueContainer"] div:has(div.stMetricLabel:contains("Overall Risk Score")) .stMetricValue {
        font-size: 4.5em !important;
        color: #d32f2f !important; /* Deep Red for high risk */
        text-shadow: none !important;
        font-weight: 900;
    }
    
    [data-testid="stMetricValueContainer"] div:has(div.stMetricLabel:contains("Overall Risk Score")) .stMetricLabel {
        color: #d32f2f;
        font-size: 1.1em;
        font-weight: 700;
    }

    </style>
    """, unsafe_allow_html=True)

# ----------------------
# Utility functions
# ----------------------
def extract_urls(text):
    # simple regex to find http/https links
    pattern = r"(https?://[^\s'\"<>]+)"
    urls = re.findall(pattern, text)
    return list(dict.fromkeys(urls))  # deduplicate, preserve order

def extract_domains(urls):
    domains = []
    for u in urls:
        try:
            ext = tldextract.extract(u)
            domain = ".".join(part for part in [ext.domain, ext.suffix] if part)
            if domain:
                domains.append(domain.lower())
        except Exception:
            continue
    return list(dict.fromkeys(domains))

def whois_lookup(domain, timeout=10):
    try:
        w = whois.whois(domain)
        # creation_date may be a list or single date
        created = w.creation_date
        registrar = w.registrar if hasattr(w, "registrar") else None
        return {"domain": domain, "whois": w, "created": created, "registrar": registrar}
    except Exception as e:
        return {"domain": domain, "error": str(e)}

def ip_lookup(domain_or_ip):
    try:
        ip = domain_or_ip
        # If input is domain, resolve it
        try:
            socket.inet_aton(domain_or_ip)
        except Exception:
            # not a plain IPv4, resolve domain (may raise)
            ip = socket.gethostbyname(domain_or_ip)
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        return {"ip": ip, "rdap": res}
    except Exception as e:
        return {"error": str(e)}

def compute_risk_score(model_pred, confidence, keywords, suspicious_domains_count, whois_ages_days):
    # Basic weighted scoring (0-100)
    score = 0.0
    # model: phishing adds weight
    score += 50.0 * (1.0 if model_pred == 1 else 0.0)
    # confidence influences
    score += 30.0 * (confidence/100.0)
    # keywords add weight
    score += min(20.0, 5.0 * len(keywords))
    # suspicious domains add small weight
    score += min(10.0, 3.0 * suspicious_domains_count)
    # old/young domain: if domain age less than 180 days => add weight
    for days in whois_ages_days:
        if days is None:
            score += 3.0
        else:
            if days < 90:
                score += 4.0
            elif days < 365:
                score += 2.0
    # clamp
    return min(100.0, round(score,2))

def format_date(d):
    if d is None:
        return "Unknown"
    if isinstance(d, list):
        d = d[0]
    if isinstance(d, datetime.date) or isinstance(d, datetime.datetime):
        return d.strftime("%Y-%m-%d")
    try:
        return str(d)
    except:
        return "Unknown"

# PDF generation
def generate_pdf_report(email_text, prediction, confidence, keywords, urls, domains_info, ip_info, score):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    c = canvas.Canvas(tmp.name, pagesize=A4)
    width, height = A4
    y = height - 40
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "Phishing Email Forensic Report")
    c.setFont("Helvetica", 10)
    y -= 20
    c.drawString(40, y, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 20
    c.drawString(40, y, f"Prediction: {'Phishing' if prediction==1 else 'Legitimate'}    Confidence: {confidence}%    Risk Score: {score}")
    y -= 25

    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Threat Keywords:")
    c.setFont("Helvetica", 10)
    y -= 18
    if keywords:
        for kw in keywords:
            c.drawString(50, y, f"- {kw}")
            y -= 14
            if y < 80:
                c.showPage(); y = height - 40
    else:
        c.drawString(50, y, "None detected"); y -= 18

    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Extracted URLs:")
    c.setFont("Helvetica", 10)
    y -= 18
    if urls:
        for u in urls:
            c.drawString(50, y, u[:100])
            y -= 12
            if y < 80:
                c.showPage(); y = height - 40
    else:
        c.drawString(50, y, "None found"); y -= 18

    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Domains WHOIS Summary:")
    c.setFont("Helvetica", 10)
    y -= 18
    for d in domains_info:
        line = f"{d.get('domain')} | Created: {format_date(d.get('created'))} | Registrar: {d.get('registrar') or 'Unknown'}"
        c.drawString(50, y, line[:120])
        y -= 12
        if y < 80:
            c.showPage(); y = height - 40

    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "IP/RDAP Summary:")
    c.setFont("Helvetica", 10)
    y -= 18
    if ip_info.get("error"):
        c.drawString(50, y, f"IP Lookup Error: {ip_info.get('error')}")
        y -= 12
    else:
        ip = ip_info.get("ip")
        org = ip_info.get("rdap", {}).get("network", {}).get("name") or ip_info.get("rdap", {}).get("entities", [{}])[0].get("vcardArray", "")
        c.drawString(50, y, f"IP: {ip} | Org: {str(org)[:100]}")
        y -= 12

    y -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Email Content (truncated):")
    y -= 14
    c.setFont("Helvetica", 9)
    lines = email_text.splitlines()
    for ln in lines[:60]:
        c.drawString(50, y, ln[:120])
        y -= 11
        if y < 80:
            c.showPage(); y = height - 40

    c.save()
    return tmp.name

# ----------------------
# Load ML artifacts (model + pipeline pieces)
# ----------------------
@st.cache_resource
def load_artifacts():
    # change names if your files differ
    model = joblib.load("lgbm_classifier.pkl")
    vectorizer = joblib.load("count_vectorizer.pkl")
    svd = joblib.load("truncated_svd.pkl")
    return model, vectorizer, svd

model, vectorizer, svd = load_artifacts()

# ----------------------
# Layout: left sidebar (controls) + main
# ----------------------
with st.sidebar:
    st.title("About SAATHI")
    st.write("Full Forensic Mode — ML + Online OSINT")
    st.markdown("**Model:** LightGBM\n**Transforms:** CountVectorizer + TruncatedSVD")
    st.markdown("---")
    if os.path.exists(NOTEBOOK_PATH):
        with open(NOTEBOOK_PATH, "rb") as nb:
            st.download_button("📥 Download Uploaded Notebook", nb, file_name="Ai_project_phising_Email.ipynb")
    st.markdown("---")
    st.markdown("**Scans (session)**")
    if "history" not in st.session_state:
        st.session_state.history = []
    for rec in reversed(st.session_state.history[-8:]):
        t = rec.get("time")
        st.write(f"- {t}: {rec.get('summary')}")

st.markdown("<div class='big-title'>🛡️ Phishing Email Forensic Scanner</div>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center; color:#9fb6c6;'>Paste an email below and run a full forensic scan (includes WHOIS & RDAP lookups).</p>", unsafe_allow_html=True)

# ----------------------
# Input area
# ----------------------
email_text = st.text_area("Paste email content here", height=320, placeholder="Full email content including headers (if available)...")

col1, col2 = st.columns([1, 3])

with col1:
    st.write("Quick tools")
    if st.button("📑 Sample Phishing (Bank)"):
        email_text = """Dear Customer,\n\nYour account has been locked due to suspicious activity. Please verify your information immediately at https://secure-bank-verify-login.com to avoid permanent closure.\n\nRegards,\nSecurity Team"""
        st.rerun()
    if st.button("📋 Sample Legitimate"):
        email_text = """Hi team,\n\nThe meeting scheduled for tomorrow has been moved to 3 PM. Please update the shared document before the session.\n\nRegards,\nProject Manager"""
        st.rerun()

with col2:
    st.write("")  # just spacing

# ----------------------
# Main action
# ----------------------
if st.button("🔍 Run Full Forensic Scan"):

    if not email_text.strip():
        st.error("Paste an email first.")
    else:
        run_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. ML prediction
        X = vectorizer.transform([email_text])
        X_svd = svd.transform(X)
        pred = model.predict(X_svd)[0]
        proba = model.predict_proba(X_svd)[0][pred]
        confidence = round(float(proba) * 100, 2)

        # 2. Extract URLs/domains
        urls = extract_urls(email_text)
        domains = extract_domains(urls)

        # 3. Keyword threat indicators
        found_keywords = [w for w in THREAT_KEYWORDS if re.search(rf"\b{re.escape(w)}\b", email_text, re.IGNORECASE)]

        # 4. WHOIS lookups (online)
        domains_info = []
        whois_ages_days = []
        for d in domains:
            info = whois_lookup(d)
            created = info.get("created")
            days = None
            if created:
                try:
                    # created may be list
                    if isinstance(created, list):
                        created = created[0]
                    if isinstance(created, str):
                        created_dt = datetime.datetime.fromisoformat(created.split(" ")[0])
                    else:
                        created_dt = created
                    days = (datetime.datetime.now() - created_dt).days
                except Exception:
                    days = None
            whois_ages_days.append(days)
            domains_info.append({"domain": d, "created": created, "registrar": info.get("registrar"), "raw": info})

        # 5. IP/RDAP for first domain (if any) or extract IPs
        ip_info = {}
        # find candidate to lookup: first domain or urls host
        candidate = None
        if domains:
            candidate = domains[0]
        else:
            # try to parse ip-like patterns in email
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", email_text)
            if ip_match:
                candidate = ip_match.group(1)

        if candidate:
            ip_info = ip_lookup(candidate)
        else:
            ip_info = {"note": "No domain/IP found to perform RDAP"}

        # 6. Risk score
        score = compute_risk_score(pred, confidence, found_keywords, len(domains), whois_ages_days)

        
        # 7. Display results in animated card
        st.markdown("<div class='result-card'>", unsafe_allow_html=True)

        # ⭐️ POP: Prediction and Score Display
        col_pred, col_score = st.columns([2, 1])

        with col_pred:
            if pred == 1:
                st.error(f"## 🚨 PHISHING DETECTED")
                score_class = "score-high"
            else:
                st.success(f"## ✅ EMAIL LIKELY LEGITIMATE")
                score_class = "score-low"
            st.markdown(f"Confidence: **{confidence}%**", unsafe_allow_html=True)

        with col_score:
            st.markdown("### Risk Score")
            st.markdown(f"<div class='{score_class}'>{score} / 100</div>", unsafe_allow_html=True)

        st.progress(min(100, int(score)))

        st.markdown("---") # Add divider for clarity

        # Show quick indicators
        st.markdown("### Threat Indicators")
        st.markdown(f"**Keywords Found:** {', '.join([f'`{k}`' for k in found_keywords]) if found_keywords else 'None'}")
        # Use st.expander for WHOIS/RDAP to keep the main view clean
        
        # ⬇️ Rest of the code uses st.expander for a cleaner look ⬇️
        
        if urls:
            with st.expander("🔗 Extracted URLs", expanded=True):
                for u in urls:
                    st.write(f"- {u}")
        else:
            st.info("No URLs extracted from content.")

        if domains_info:
            with st.expander("👤 Domain WHOIS Summary", expanded=False):
                for di in domains_info[:6]:
                    st.markdown(f"- **{di.get('domain')}** — Created: **{format_date(di.get('created'))}** — Registrar: *{di.get('registrar') or 'Unknown'}*")
        else:
            st.info("No domains to WHOIS lookup.")

        # ... continue with the IP/RDAP display inside a separate expander if needed ...
        
        # Original IP/RDAP section:

        st.write("### IP / RDAP Info (Primary Host)")
        if ip_info.get("error"):
            st.write("IP lookup failed:", ip_info.get("error"))
        elif ip_info.get("note"):
            st.write(ip_info.get("note"))
        else:
            ip_val = ip_info.get("ip") or "Unknown"
            rd = ip_info.get("rdap") or {}
            network = rd.get("network") or {}
            org_name = network.get("name") or rd.get("entities")
            st.write(f"**IP:** {ip_val}")
            st.write(f"**Organization:** {org_name}")


        st.markdown("</div>", unsafe_allow_html=True)

        # 8. Save to session history
        rec = {
            "time": run_time,
            "summary": f"{'PHISH' if pred==1 else 'LEGIT'} | {confidence}% | score {score}",
            "full": {
                "text": email_text,
                "pred": int(pred),
                "confidence": confidence,
                "score": score,
                "keywords": found_keywords,
                "urls": urls,
                "domains_info": domains_info,
                "ip_info": ip_info
            }
        }
        st.session_state.history.append(rec)

        # 9. PDF report and download
        pdf_path = generate_pdf_report(email_text, pred, confidence, found_keywords, urls, domains_info, ip_info, score)
        with open(pdf_path, "rb") as f:
            st.download_button("📄 Download Forensic PDF Report", f, file_name=f"saathi_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf", mime="application/pdf")

        # cleanup temp file on exit (optional)
        try:
            os.remove(pdf_path)
        except Exception:
            pass

# ----------------------
# Footer / tips
# ----------------------
st.markdown("---")
st.markdown("**Tips:** Provide full headers (From/To/Subject) in the pasted text for richer metadata heuristics. WHOIS/RDAP queries require internet access and may be rate-limited.")
# ----------------------
