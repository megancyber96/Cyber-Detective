import ipaddress
import json
import html
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="Cyber Detective v1.0", page_icon="🕵️", layout="wide", initial_sidebar_state="expanded")

BRANDS = {"paypal": "paypal.com", "google": "google.com", "microsoft": "microsoft.com", "apple": "apple.com", "amazon": "amazon.com"}


def analyze_url(raw_url):
    value = raw_url.strip()
    if not value:
        raise ValueError("Please enter a URL.")
    if any(ch.isspace() for ch in value):
        raise ValueError("URL must not contain whitespace.")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port  # validates invalid port numbers
    except ValueError as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Enter a full URL beginning with http:// or https://")
    if not hostname:
        raise ValueError("Missing hostname.")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid port.")

    domain = hostname.lower().rstrip(".")
    findings = []

    def flag(name, points, explanation):
        findings.append({"name": name, "points": points, "explanation": explanation})

    for brand, official_domain in BRANDS.items():
        if brand in domain and domain != official_domain and not domain.endswith("." + official_domain):
            flag(f"Possible {brand.title()} impersonation", 35,
                 f"Hostname mentions {brand.title()}, but is not {official_domain} or its subdomain. This is a clue, not proof of phishing.")
    if parsed.scheme.lower() == "http":
        flag("No HTTPS", 20, "The URL uses HTTP instead of HTTPS. HTTPS alone does not prove a website is safe.")
    try:
        ipaddress.ip_address(domain)
        flag("IP address instead of domain", 25, "The hostname is a numeric IP address; this can be legitimate but deserves scrutiny.")
    except ValueError:
        pass
    if "xn--" in domain:
        flag("Punycode domain", 20, "The hostname uses IDN/Punycode encoding; verify it visually to rule out lookalike domains.")
    if parsed.username is not None or parsed.password is not None:
        flag("URL contains userinfo", 25, "Text before an @ symbol may disguise the actual hostname.")
    if len(value) > 120:
        flag("Unusually long URL", 10, "Very long URLs can be used to obscure important details, but may also be normal.")
    if re.search(r"%[0-9a-fA-F]{2}", parsed.netloc):
        flag("Encoded hostname characters", 15, "Encoded characters in the network location may make the address harder to inspect.")

    score = min(100, sum(item["points"] for item in findings))
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 25 else "LOW"
    return {"url": value, "hostname": domain, "score": score, "level": level,
            "findings": findings, "scanned_at": datetime.now(timezone.utc).isoformat(),
            "method": "Offline URL-string heuristics only; no website requests, reputation lookup, or malware scan."}




st.markdown("""
<style>
.stApp {background:radial-gradient(ellipse at 65% 0%,#0d3043 0%,#050d19 45%,#03070f 100%);color:#dcefff}
[data-testid="stSidebar"] {background:#071321;border-right:1px solid #235168}
[data-testid="stHeader"] {background:transparent}
h1,h2,h3 {color:#e4f7ff!important}
.hero {border:1px solid #226783;border-radius:18px;padding:28px;background:linear-gradient(120deg,#081b2c,#10132b);box-shadow:0 0 45px #00bde51b;margin:0 0 24px}
.kicker {font-size:12px;letter-spacing:3px;color:#75d8e7;font-weight:700}
.hero-title {font-size:clamp(32px,5vw,60px);font-weight:900;letter-spacing:3px;line-height:1.18;color:#e9faff}
.hero-title span {color:#ff536b;text-shadow:0 0 22px #ff536b66}
.sub {color:#8bb6c9;font-size:13px;margin-top:12px}
.panel {border:1px solid #245e79;border-radius:16px;padding:20px;background:#071b2bbf;box-shadow:inset 0 0 28px #00c6e50b}
.radar {height:190px;width:190px;max-width:100%;aspect-ratio:1;border-radius:50%;margin:16px auto;border:2px solid #17c6da;position:relative;overflow:hidden;background:repeating-radial-gradient(circle,transparent 0 27px,#14778b80 28px 29px),linear-gradient(90deg,transparent 49.5%,#16758a 50%,transparent 50.5%),linear-gradient(transparent 49.5%,#16758a 50%,transparent 50.5%),#061d2a;box-shadow:0 0 25px #00d9ff33}
.radar:before {content:"";position:absolute;inset:0;background:conic-gradient(transparent 0deg,transparent 270deg,#00eeff12 300deg,#00eeff8a 360deg);animation:sweep 4s linear infinite}
.radar:after {content:"●";position:absolute;left:67%;top:32%;color:#ff536b;text-shadow:0 0 12px red;animation:blink 1.2s infinite alternate}
@keyframes sweep {to {transform:rotate(360deg)}}
@keyframes blink {to {opacity:.15}}
.alert-high {border:1px solid #ff566d;border-left:7px solid #ff405b;border-radius:15px;padding:24px;background:linear-gradient(90deg,#481323,#1b1021);box-shadow:0 0 28px #ff36512e;animation:glow 1.4s infinite alternate}
.alert-medium {border:1px solid #ffc069;border-radius:14px;padding:20px;background:#342515}
.alert-low {border:1px solid #4bceae;border-radius:14px;padding:20px;background:#0b302c}
.alert-title {font-size:clamp(20px,3vw,32px);font-weight:900;letter-spacing:1px}
@keyframes glow {to {box-shadow:0 0 42px #ff36517a;border-color:#ff8b9c}}
.finding {border-left:4px solid #ffba63;background:#211d21;border-radius:8px;padding:14px;margin:10px 0}
.small {font-size:12px;color:#9abfce}
@media(prefers-reduced-motion:reduce){.radar:before,.radar:after,.alert-high{animation:none!important}}
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### 🕵️ CYBER DETECTIVE")
    st.caption("INTELLIGENCE CONSOLE · v1.0")
    st.success("● SYSTEM ONLINE")
    st.markdown("**MODULES**")
    st.write("🔎 URL inspection — active")
    st.write("📡 Radar — decorative")
    st.write("🚨 Visual risk alerts — active")
    st.write("📄 JSON reports — active")
    st.write("🗂️ Session scan history — active")
    st.divider()
    st.caption("Offline URL-text analysis only. No website is contacted; no live threat feed is connected.")

st.markdown('<div class="hero"><div class="kicker">◈ SECURITY OPERATIONS / URL INTELLIGENCE</div><div class="hero-title">🕵️ CYBER <span>DETECTIVE</span></div><div class="sub">V1.0 · OFFLINE HEURISTIC ANALYSIS · MISSION CONTROL</div></div>', unsafe_allow_html=True)

left, right = st.columns([2.4, 1], gap="large")
with left:
    st.markdown("### 🔗 TARGET INSPECTION")
    st.caption("Analyze a URL for suspicious text patterns without visiting the website.")
    with st.form("scan_form"):
        url = st.text_input("Target URL", placeholder="https://example.com")
        submitted = st.form_submit_button("🔍 INITIATE SCAN", type="primary", use_container_width=True)
with right:
    st.markdown('<div class="panel"><b>📡 SIGNAL RADAR</b><div class="radar"></div><div class="small" style="text-align:center">VISUAL SIMULATION · NOT LIVE DATA</div></div>', unsafe_allow_html=True)

if "history" not in st.session_state:
    st.session_state["history"] = []

if submitted:
    try:
        scan_result = analyze_url(url)
        st.session_state["result"] = scan_result
        st.session_state["history"].insert(0, scan_result)
        st.session_state["history"] = st.session_state["history"][:25]
    except ValueError as exc:
        st.session_state.pop("result", None)
        st.error(str(exc))

controls_left, controls_right = st.columns([1, 1])
with controls_left:
    if st.button("🧹 CLEAR CURRENT RESULT", use_container_width=True):
        st.session_state.pop("result", None)
        st.rerun()
with controls_right:
    if st.button("🗑️ CLEAR SCAN HISTORY", use_container_width=True):
        st.session_state["history"] = []
        st.rerun()

result = st.session_state.get("result")
if result:
    st.divider()
    level = result["level"]
    if level == "HIGH":
        st.markdown('<div class="alert-high"><div class="kicker">🚨 SECURITY ALERT · HIGH PRIORITY</div><div class="alert-title">HIGH RISK INDICATORS DETECTED</div><div>Verify this URL independently before proceeding.</div></div>', unsafe_allow_html=True)
    elif level == "MEDIUM":
        st.markdown('<div class="alert-medium"><div class="alert-title">⚠️ SUSPICIOUS INDICATORS</div>Review the findings carefully.</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="alert-low"><div class="alert-title">🟢 NO LISTED INDICATORS</div>This does not establish that the website is safe.</div>', unsafe_allow_html=True)

    st.markdown("### 🛡️ SECURITY ANALYSIS")
    a, b, c = st.columns(3)
    a.metric("Heuristic score", f'{result["score"]}/100')
    b.metric("Risk level", level)
    c.metric("Indicators", len(result["findings"]))
    color = {"HIGH":"#ff536b","MEDIUM":"#ffba63","LOW":"#49d9b5"}[level]
    chart = go.Figure(go.Indicator(mode="gauge+number", value=result["score"],
        number={"font":{"color":"#e5faff","size":44}},
        gauge={"axis":{"range":[0,100],"tickcolor":"#8da8b6"},
               "bar":{"color":color},"bgcolor":"#071c2b",
               "steps":[{"range":[0,25],"color":"#123d38"},
                        {"range":[25,60],"color":"#55401b"},
                        {"range":[60,100],"color":"#531c2a"}]}))
    chart.update_layout(height=265,margin=dict(l=25,r=25,t=20,b=10),paper_bgcolor="rgba(0,0,0,0)",font={"color":"#d9f5ff"})
    st.plotly_chart(chart,width="stretch",config={"displayModeBar":False})
    st.write(f'**Target hostname:** `{result["hostname"]}`')
    st.markdown("### 🔎 FINDINGS")
    if result["findings"]:
        for item in result["findings"]:
            name = html.escape(item["name"])
            explanation = html.escape(item["explanation"])
            st.markdown(f'<div class="finding"><b>⚠️ {name} (+{item["points"]})</b><div class="small">{explanation}</div></div>',unsafe_allow_html=True)
    else:
        st.info("No indicators detected by the current rules.")
    st.caption("⚠️ This heuristic score is not a probability of maliciousness. No TLS verification, malware scanning, website visit, or reputation lookup is performed.")
    st.download_button("⬇️ DOWNLOAD JSON REPORT",data=json.dumps(result,indent=2,ensure_ascii=False),file_name="cyber_detective_report.json",mime="application/json")
else:
    st.caption("Ready to scan. Try https://paypal-login.example.org (a demonstration URL, not a real threat feed).")


st.divider()
st.markdown("### 🗂️ RECENT SCANS")
st.caption("Stored only during this app session (up to 25 scans). Not saved to disk.")
if st.session_state["history"]:
    for idx, scan in enumerate(st.session_state["history"][:10], start=1):
        st.markdown(
            f"**{idx}. {html.escape(scan['hostname'])}** · "
            f"{scan['level']} · {scan['score']}/100 · "
            f"{html.escape(scan['scanned_at'][:19].replace('T', ' '))} UTC"
        )
    st.download_button(
        "⬇️ DOWNLOAD SESSION HISTORY (JSON)",
        data=json.dumps(st.session_state["history"], indent=2, ensure_ascii=False),
        file_name="cyber_detective_history.json",
        mime="application/json",
    )
else:
    st.caption("No scans in this session yet.")


# Project signature
st.divider()
st.markdown(
    """<div style="text-align:center;padding:18px 8px 26px;color:#9abfce;">
      <div style="font-weight:800;letter-spacing:2px;color:#e4f7ff;">🕵️ CYBER DETECTIVE v1.0</div>
      <div style="margin-top:8px;font-size:13px;">Designed &amp; Developed by Megan © 2026</div>
    </div>""",
    unsafe_allow_html=True,
)

# Hide Streamlit chrome; may require updates on future Streamlit releases.
st.markdown("""
<style>
#MainMenu {visibility: hidden;}
.stDeployButton {display: none;}
[data-testid="stToolbar"] {display: none;}
footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)
