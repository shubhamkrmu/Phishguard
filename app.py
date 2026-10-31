# app.py
import html
import json
import time
import streamlit as st
import pandas as pd
import joblib
from pathlib import Path

from features import extract_features
from live_checks import (get_host, dns_check, is_private_ip, ssl_check,
                         domain_age_days, fetch_page, analyze_html, risk_signals)
from db import (init_db, normalize, get_scan, save_scan, bump_scan,
                get_scans_by_ids, db_stats)

st.set_page_config(page_title="PhishGuard | Phishing URL Detector",
                   page_icon="🛡️", layout="wide")
init_db()
CACHE_TTL = 24 * 3600          # saved result 24 ghante tak reuse hoga


def html_block(s: str):
    s = " ".join(line.strip() for line in s.splitlines() if line.strip())
    if hasattr(st, "html"):
        st.html(s)
    else:
        st.markdown(s, unsafe_allow_html=True)


def esc(x) -> str:
    return html.escape(str(x))


# ------------------------------------------------------------ styling
html_block("""
<style>
.stApp {background: linear-gradient(180deg,#EEF2FF 0%,#FDF2F8 55%,#ECFEFF 100%);}
#MainMenu, footer {visibility: hidden;}
.block-container {padding-top: 2rem; max-width: 860px;}
section[data-testid="stSidebar"] {background: #FFFFFF; border-right: 1px solid #E5E7EB;}

.hero {background: linear-gradient(135deg,#4F46E5 0%,#7C3AED 55%,#06B6D4 100%);
  border-radius: 22px; padding: 34px 32px; color: #fff; margin-bottom: 22px;
  box-shadow: 0 12px 32px rgba(79,70,229,.30);}
.hero h1 {margin: 0; font-size: 2.3rem; font-weight: 800; color: #fff !important;}
.hero p {margin: 8px 0 0 0; font-size: 1.05rem; color: #fff; opacity: .93;}
.hero .tags span {display: inline-block; background: rgba(255,255,255,.2);
  border-radius: 999px; padding: 5px 13px; margin: 16px 8px 0 0; font-size: .82rem; color: #fff;}

.result {display: flex; align-items: center; gap: 26px; flex-wrap: wrap;
  border-radius: 20px; padding: 24px 28px; margin: 16px 0;
  box-shadow: 0 8px 26px rgba(17,24,39,.10);}
.ring {width: 150px; height: 150px; border-radius: 50%; display: flex;
  align-items: center; justify-content: center; flex-shrink: 0;}
.ring-inner {width: 118px; height: 118px; border-radius: 50%; background: #fff;
  display: flex; flex-direction: column; align-items: center; justify-content: center;}
.score {font-size: 2.4rem; font-weight: 800; line-height: 1;}
.outof {font-size: .78rem; color: #9CA3AF;}
.vtitle {font-size: 1.5rem; font-weight: 800;}
.vsub {color: #4B5563; margin-top: 6px; font-size: .98rem;}

.dbtag {display: inline-block; border-radius: 10px; padding: 7px 14px; margin: 2px 0 8px 0;
  font-size: .86rem; font-weight: 700;}
.dbtag-hit {background: #E0F2FE; color: #075985;}
.dbtag-new {background: #DCFCE7; color: #166534;}
.dbtag-re {background: #FEF3C7; color: #92400E;}

.mini {display: flex; gap: 14px; flex-wrap: wrap; margin: 4px 0 14px 0;}
.mini .box {flex: 1; min-width: 200px; background: #fff; border-radius: 16px;
  padding: 16px 18px; box-shadow: 0 4px 18px rgba(17,24,39,.07);}
.mini .lbl {color: #6B7280; font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; font-weight: 700;}
.mini .val {font-size: 1.7rem; font-weight: 800; margin-top: 4px;}
.bar {height: 9px; background: #E5E7EB; border-radius: 999px; margin-top: 10px; overflow: hidden;}
.bar > div {height: 100%; border-radius: 999px;}

.card {background: #fff; border-radius: 18px; padding: 20px 24px; margin: 14px 0;
  box-shadow: 0 4px 18px rgba(17,24,39,.07);}
.card.blue {border-left: 6px solid #4F46E5;}
.card.red {border-left: 6px solid #EF4444;}
.sec {font-size: 1.08rem; font-weight: 800; margin: 0 0 10px 0; color: #111827;}
.sbtitle {font-size: 1rem; font-weight: 800; color: #111827; margin: 6px 0 8px 0;}

.chip {display: inline-block; border-radius: 999px; padding: 6px 14px; margin: 4px 8px 4px 0;
  font-size: .85rem; font-weight: 700;}
.chip-blue {background: #DBEAFE; color: #1E40AF;}
.chip-purple {background: #EDE9FE; color: #5B21B6;}
.chip-green {background: #D1FAE5; color: #065F46;}
.chip-red {background: #FEE2E2; color: #991B1B;}
.chip-orange {background: #FFEDD5; color: #9A3412;}
.chip-gray {background: #F3F4F6; color: #374151;}

.reason {display: flex; gap: 12px; align-items: center; padding: 10px 0; border-bottom: 1px solid #F1F2F7; color: #1F2937;}
.reason:last-child {border-bottom: none;}
.pill {font-weight: 800; border-radius: 8px; padding: 3px 10px; font-size: .82rem; min-width: 46px; text-align: center;}
.pill-high {background: #FEE2E2; color: #B91C1C;}
.pill-mid {background: #FFEDD5; color: #C2410C;}
.pill-low {background: #FEF9C3; color: #A16207;}
.ok {color: #047857; font-weight: 700;}
.foot {text-align: center; color: #6B7280; font-size: .82rem; margin-top: 30px;}

div[data-baseweb="input"] {border-radius: 12px !important; border: 2px solid #C7D2FE !important; background: #fff !important;}
button[kind="primary"], button[data-testid="stBaseButton-primary"] {
  background: linear-gradient(135deg,#4F46E5,#7C3AED) !important; border: none !important;
  border-radius: 12px !important; padding: .55rem 1.8rem !important; box-shadow: 0 6px 16px rgba(79,70,229,.35);}
button[kind="primary"] p, button[data-testid="stBaseButton-primary"] p {color: #fff !important; font-weight: 700 !important;}
button[kind="secondary"], button[data-testid="stBaseButton-secondary"] {
  background: #EEF2FF !important; border: 1px solid #C7D2FE !important; border-radius: 12px !important;}
button[kind="secondary"] p, button[data-testid="stBaseButton-secondary"] p {color: #3730A3 !important; font-weight: 600 !important;}
button[kind="secondary"]:hover, button[data-testid="stBaseButton-secondary"]:hover {background: #E0E7FF !important;}
</style>
""")

# ------------------------------------------------------------ config
TRUSTED = {
    "google.com", "youtube.com", "instagram.com", "facebook.com", "github.com",
    "wikipedia.org", "amazon.in", "amazon.com", "microsoft.com", "apple.com",
    "linkedin.com", "twitter.com", "x.com", "whatsapp.com", "netflix.com",
    "flipkart.com", "paytm.com", "gov.in", "nic.in", "stackoverflow.com",
}
USER_CONTENT_HOSTS = {          # jahan koi bhi content daal sakta hai, auto-trust nahi
    "drive.google.com", "docs.google.com", "sites.google.com", "forms.gle",
    "forms.google.com", "storage.googleapis.com", "script.google.com",
    "github.io", "raw.githubusercontent.com", "gist.github.com",
    "blogspot.com", "sharepoint.com", "onedrive.live.com",
}
EXAMPLES = {
    "Fake bank login": "http://secure.sbi-netbanking-update.info/login.html",
    "Fake PayPal": "http://paypal-secure-login.verify-account-update.top/signin",
    "IP address URL": "http://192.168.45.12/bank/login/confirm.php?id=8821",
    "Real site": "https://example.com",
}


def is_trusted(host: str) -> bool:
    if any(host == d or host.endswith("." + d) for d in USER_CONTENT_HOSTS):
        return False
    return any(host == d or host.endswith("." + d) for d in TRUSTED)


@st.cache_resource
def load_model():
    p = Path(__file__).parent / "url_model.pkl"
    if not p.exists():
        st.error(f"Model file not found: {p}")
        st.stop()
    return joblib.load(p)


model = load_model()


def colour_for(score: float):
    if score >= 60:
        return "#DC2626", "#FEF2F2", "High phishing risk", "⚠️"
    if score >= 35:
        return "#D97706", "#FFFBEB", "Suspicious", "🟠"
    return "#059669", "#ECFDF5", "Looks safe", "✅"


def chip(text, cls):
    return f"<span class='chip chip-{cls}'>{esc(text)}</span>"


def fmt_time(ts):
    return time.strftime("%d %b %Y, %H:%M", time.localtime(ts))


# ------------------------------------------------------------ scanning
def run_scan(nurl: str, host: str, deep: bool) -> dict:
    """Poora scan. Result ek dict hai jo database mein JSON ban ke save hota hai."""
    base = {"host": host, "deep": deep, "chips": [], "reasons": [], "note": ""}

    if is_trusted(host):
        return {**base, "kind": "trusted", "final": 0.0, "model_risk": 0.0, "live_risk": 0.0}

    X = pd.DataFrame([extract_features(nurl)])
    model_risk = (1 - float(model.predict_proba(X)[0, 1])) * 100      # label 1 = Legit
    live_risk, reasons, chips, note = 0.0, [], [], ""

    if deep:
        ip = dns_check(host)
        if ip is None:
            return {**base, "kind": "nodns", "final": 100.0,
                    "model_risk": model_risk, "live_risk": 100.0}

        age = domain_age_days(host)
        https_info = ssl_check(host)
        page = content = None
        if is_private_ip(ip):
            note = "Private or local IP address. Page fetch skipped for safety."
        else:
            page = fetch_page(nurl)
            if page and "error" in page:
                note = f"Could not fetch the page: {page['error']}"
            elif page:
                content = analyze_html(page["html"], page["final_url"])

        reasons = risk_signals(host, ip, https_info, age, page, content, nurl)
        live_risk = float(min(sum(p for p, _ in reasons), 100))

        chips.append([f"IP: {ip}", "blue"])
        if age is None:
            chips.append(["Domain age: unknown", "gray"])
        else:
            chips.append([f"Domain age: {age} days", "red" if age < 30 else "orange" if age < 180 else "green"])
        chips.append([f"SSL: {https_info['issuer']}", "green"] if https_info else ["SSL: invalid or none", "red"])
        if content and content["title"]:
            chips.append([f"Title: {content['title'][:50]}", "purple"])

    final = (0.5 * model_risk + 0.5 * live_risk) if deep else model_risk
    return {**base, "kind": "scan", "final": final, "model_risk": model_risk,
            "live_risk": live_risk, "chips": chips, "reasons": [list(r) for r in reasons], "note": note}


# ------------------------------------------------------------ rendering
def result_card(title, subtitle, score, color, bg, icon):
    html_block(f"""
    <div class="result" style="background:{bg}; border-left:8px solid {color};">
      <div class="ring" style="background:conic-gradient({color} {score * 3.6}deg,#E5E7EB 0deg);">
        <div class="ring-inner">
          <span class="score" style="color:{color}">{score:.0f}</span>
          <span class="outof">/ 100 risk</span>
        </div>
      </div>
      <div>
        <div class="vtitle" style="color:{color}">{icon} {esc(title)}</div>
        <div class="vsub">{esc(subtitle)}</div>
      </div>
    </div>
    """)


def mini_boxes(model_risk, live_risk, deep):
    mc = colour_for(model_risk)[0]
    live_html = "<div class='val' style='color:#9CA3AF'>off</div>"
    if deep:
        lc = colour_for(live_risk)[0]
        live_html = (f"<div class='val' style='color:{lc}'>{live_risk:.0f}<span class='outof'> / 100</span></div>"
                     f"<div class='bar'><div style='width:{live_risk}%;background:{lc}'></div></div>")
    html_block(f"""
    <div class="mini">
      <div class="box"><div class="lbl">🤖 URL pattern model</div>
        <div class="val" style="color:{mc}">{model_risk:.0f}<span class="outof"> / 100</span></div>
        <div class="bar"><div style="width:{model_risk}%;background:{mc}"></div></div></div>
      <div class="box"><div class="lbl">🌐 Live checks</div>{live_html}</div>
    </div>
    """)


def render(rec: dict, nurl: str):
    kind, final = rec["kind"], rec["final"]
    if kind == "trusted":
        result_card("Trusted domain", f"{rec['host']} is on the known popular sites list.",
                    0, "#059669", "#ECFDF5", "✅")
        return
    if kind == "nodns":
        result_card("Domain does not exist", "The DNS lookup failed, so this link leads nowhere.",
                    100, "#DC2626", "#FEF2F2", "❌")
        return

    color, bg, label, icon = colour_for(final)
    result_card(label, f"Combined score for {rec['host']}", final, color, bg, icon)
    mini_boxes(rec["model_risk"], rec["live_risk"], rec["deep"])

    if rec["deep"]:
        chips = "".join(chip(t, c) for t, c in rec["chips"])
        html_block(f"<div class='card blue'><div class='sec'>🔎 Findings</div>{chips}</div>")
        if rec["note"]:
            st.info(rec["note"])
        if rec["reasons"]:
            rows = ""
            for p, t in sorted(rec["reasons"], reverse=True):
                cls = "high" if p >= 20 else "mid" if p >= 10 else "low"
                rows += f"<div class='reason'><span class='pill pill-{cls}'>+{p}</span><span>{esc(t)}</span></div>"
            html_block(f"<div class='card red'><div class='sec'>🚩 Risk reasons</div>{rows}</div>")
        else:
            html_block("<div class='card blue'><div class='sec'>🚩 Risk reasons</div>"
                       "<span class='ok'>No major red flags found.</span></div>")

    with st.expander("Features extracted by the URL model"):
        st.dataframe(pd.DataFrame([extract_features(nurl)]).T.astype(str), use_container_width=True)


# ------------------------------------------------------------ session state
if "url_input" not in st.session_state:
    st.session_state.url_input = ""
if "history" not in st.session_state:
    st.session_state.history = []          # sirf is browser session ke scan ids


def set_url(u):
    st.session_state.url_input = u


def clear_history():
    st.session_state.history = []


# ------------------------------------------------------------ main page
html_block("""
<div class="hero">
  <h1>🛡️ PhishGuard</h1>
  <p>Paste any link and find out if it looks like phishing, before you click it.</p>
  <div class="tags"><span>🤖 ML URL model</span><span>🌐 DNS · WHOIS · SSL</span><span>📄 Page content scan</span><span>🗄️ Scan database</span></div>
</div>
""")

url = st.text_input("Paste a URL", key="url_input", placeholder="https://example.com/login")
deep = st.checkbox("Deep scan (fetch live DNS, WHOIS, SSL and page HTML)", value=True)

st.caption("Try an example (made-up links, safe to test):")
cols = st.columns(len(EXAMPLES))
for col, (label, u) in zip(cols, EXAMPLES.items()):
    col.button(label, on_click=set_url, args=(u,), use_container_width=True, key=f"ex_{label}")

go = st.button("🔍 Check URL", type="primary")

if go:
    if not url.strip():
        st.warning("Please enter a URL first.")
    else:
        nurl = normalize(url)
        host = get_host(nurl)
        force = st.session_state.get("force_rescan", False)

        cached = None if force else get_scan(nurl)
        use_cache = bool(cached
                         and time.time() - cached["scanned_at"] < CACHE_TTL
                         and (cached["deep"] or not deep))       # deep result, shallow se behtar hai

        if use_cache:
            rec = json.loads(cached["details"])
            bump_scan(cached["id"])
            scan_id, mode = cached["id"], "hit"
        else:
            with st.spinner("Checking domain and page (5-15 seconds)..."):
                rec = run_scan(nurl, host, deep)
            verdict = {"trusted": "Trusted", "nodns": "Domain does not exist"}.get(
                rec["kind"], colour_for(rec["final"])[2])
            scan_id = save_scan(nurl, host, rec["final"], verdict, deep, rec)
            mode = "re" if get_scan(nurl) and cached else "new"

        row = get_scan(nurl)
        st.session_state.history = ([scan_id] + [i for i in st.session_state.history if i != scan_id])[:15]

        if mode == "hit":
            html_block(f"<span class='dbtag dbtag-hit'>🗄️ Found in database · checked {row['times_checked']} times · "
                       f"first seen {fmt_time(row['first_seen'])}</span>")
        elif mode == "re":
            html_block("<span class='dbtag dbtag-re'>🔄 Old record was stale, re-scanned and database updated</span>")
        else:
            html_block("<span class='dbtag dbtag-new'>🆕 New URL · scanned and saved to database</span>")

        render(rec, nurl)

html_block("<div class='foot'>Academic project. Risk weights are hand-set. "
           "Not a replacement for a real security tool. Do not paste links that contain personal tokens.</div>")

# ------------------------------------------------------------ sidebar (hamesha aakhir mein, taaki latest scan dikhe)
with st.sidebar:
    stats = db_stats()
    html_block("<div class='sbtitle'>🗄️ Scan database</div>")
    c1, c2 = st.columns(2)
    c1.metric("URLs stored", stats["total"])
    c2.metric("Flagged risky", stats["risky"])
    st.caption(f"Total checks so far: {stats['checks']}")

    html_block("<div class='sbtitle'>🕘 Your recent checks</div>")
    rows = get_scans_by_ids(st.session_state.history)
    if not rows:
        st.caption("No checks yet. Scan a URL and it will show up here.")
    for r in rows:
        dot = "🔴" if r["risk"] >= 60 else "🟠" if r["risk"] >= 35 else "🟢"
        short = r["url"].split("://", 1)[-1]
        short = short if len(short) <= 28 else short[:27] + "…"
        st.button(f"{dot} {r['risk']:.0f}%  {short}", key=f"hist_{r['id']}",
                  on_click=set_url, args=(r["url"],), use_container_width=True)
    if rows:
        st.button("Clear my history", on_click=clear_history, key="clear_hist")

    st.divider()
    st.checkbox("Ignore saved result (force fresh scan)", key="force_rescan")