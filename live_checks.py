# live_checks.py
import socket, ssl, re, ipaddress, warnings
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
import tldextract
import whois

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; PhishingCheckerDemo/1.0)"}
MAX_BYTES = 1_500_000


def get_host(url: str) -> str:
    u = url.strip()
    return urlparse(u if '://' in u else 'http://' + u).netloc.lower().split(':')[0]


def reg_domain(host: str) -> str:
    ext = tldextract.extract(host)
    return getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or host


def dns_check(host: str):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except Exception:
        return True


def ssl_check(host: str):
    """HTTPS certificate info. None = HTTPS nahi chala / cert invalid."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
        nb = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notBefore']), tz=timezone.utc)
        na = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), tz=timezone.utc)
        issuer = dict(x[0] for x in cert.get('issuer', []))
        return {"issued_days_ago": (datetime.now(timezone.utc) - nb).days,
                "expires_in_days": (na - datetime.now(timezone.utc)).days,
                "issuer": issuer.get('organizationName', 'unknown')}
    except Exception:
        return None


def domain_age_days(host: str):
    try:
        w = whois.whois(reg_domain(host))
        c = w.creation_date
        if isinstance(c, list):
            c = c[0]
        if c is None:
            return None
        if c.tzinfo is None:
            c = c.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - c).days
    except Exception:
        return None


def fetch_page(url: str):
    """Download HTML only (no JS runs). Every redirect hop is checked against private IPs."""
    u = url.strip()
    if '://' not in u:
        u = 'http://' + u
    hops = []
    try:
        for _ in range(5):
            ip = dns_check(get_host(u))
            if ip is None or is_private_ip(ip):
                return {"error": "Blocked: unresolvable or private address"}
            r = requests.get(u, headers=HEADERS, timeout=8, stream=True,
                             allow_redirects=False, verify=False)
            if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                hops.append(u)
                u = urljoin(u, r.headers["Location"])
                r.close()
                continue
            break
        else:
            return {"error": "Too many redirects"}
    except Exception as e:
        return {"error": e.__class__.__name__}

    data = b""
    for chunk in r.iter_content(8192):
        data += chunk
        if len(data) > MAX_BYTES:
            break
    r.close()
    return {"final_url": u, "status": r.status_code, "redirects": hops,
            "html": data.decode(r.encoding or "utf-8", errors="ignore")}


def analyze_html(html: str, final_url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    base = reg_domain(get_host(final_url))

    forms = soup.find_all("form")
    pw_inputs = soup.find_all("input", attrs={"type": re.compile("^password$", re.I)})
    bad_action = ext_action = 0
    for f in forms:
        act = (f.get("action") or "").strip()
        if act in ("", "#") or act.lower().startswith("javascript"):
            bad_action += 1
        elif reg_domain(get_host(urljoin(final_url, act))) != base:
            ext_action += 1

    links = [a.get("href", "") for a in soup.find_all("a", href=True)]
    links = [urljoin(final_url, l) for l in links if l.startswith(("http", "/"))]
    ext_links = [l for l in links if reg_domain(get_host(l)) != base]

    text = soup.get_text(" ", strip=True).lower()
    icon = soup.find("link", rel=lambda v: v and "icon" in (" ".join(v) if isinstance(v, list) else v).lower())
    refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})

    return {
        "title": (soup.title.string or "").strip() if soup.title and soup.title.string else "",
        "has_password_field": len(pw_inputs) > 0,
        "forms": len(forms),
        "form_empty_action": bad_action,
        "form_external_action": ext_action,
        "iframes": len(soup.find_all("iframe")),
        "scripts": len(soup.find_all("script")),
        "total_links": len(links),
        "external_link_ratio": (len(ext_links) / len(links)) if links else 0.0,
        "has_favicon": icon is not None,
        "has_copyright": ("©" in text) or ("copyright" in text),
        "meta_refresh": refresh is not None,
        "html_length": len(html),
    }


def risk_signals(host, ip, https_info, age, page, content, url):
    """List of (points, reason). Total risk is capped at 100. Weights are hand-set."""
    r = []
    if age is not None:
        if age < 30:
            r.append((30, f"Domain is very new ({age} days old)"))
        elif age < 180:
            r.append((15, f"Domain is fairly new ({age} days old)"))
    else:
        r.append((8, "Domain age could not be determined (WHOIS hidden or failed)"))

    if not url.lower().startswith("https"):
        r.append((10, "URL does not use HTTPS"))
    if https_info is None:
        r.append((12, "No valid SSL certificate found"))
    elif https_info["issued_days_ago"] < 14:
        r.append((8, f"SSL certificate was issued only {https_info['issued_days_ago']} days ago"))

    if page and "error" not in page:
        if len(page["redirects"]) > 0 and reg_domain(get_host(page["final_url"])) != reg_domain(host):
            r.append((12, f"Redirects to a different domain: {get_host(page['final_url'])}"))
        if content:
            if content["has_password_field"] and content["form_external_action"] > 0:
                r.append((25, "Password form sends data to a different domain"))
            elif content["has_password_field"] and content["form_empty_action"] > 0:
                r.append((12, "Password form has an empty or suspicious action"))
            if content["has_password_field"] and not url.lower().startswith("https"):
                r.append((10, "Password requested without HTTPS"))
            if content["iframes"] >= 3:
                r.append((6, f"Many iframes on the page ({content['iframes']})"))
            if content["external_link_ratio"] > 0.8 and content["total_links"] >= 5:
                r.append((8, "Most links point to other domains"))
            if content["meta_refresh"]:
                r.append((6, "Page auto-redirects using meta refresh"))
            if not content["has_favicon"] and not content["has_copyright"]:
                r.append((5, "No favicon and no copyright notice (low-effort page)"))
    return r