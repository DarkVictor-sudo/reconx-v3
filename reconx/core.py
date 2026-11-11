import re, random, urllib.parse
import httpx

UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
       "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"]

def balance(p, mode="plain"):
    """URL balancer: +and+0 style encodings"""
    return {"plain": p, "plus": urllib.parse.quote_plus(p), "encode": urllib.parse.quote(p),
            "double": urllib.parse.quote(urllib.parse.quote(p)),
            "comment": p.replace(" ", "/**/")}.get(mode, p)

TAMPERS = {
    "plain": lambda p: p,
    "space2comment": lambda p: p.replace(" ", "/**/"),
    "randomcase": lambda p: "".join(c.upper() if random.random() < .5 else c.lower() for c in p),
    "eq2like": lambda p: re.sub(r"=", " LIKE ", p, count=1),
    "doubleencode": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
    "space2plus": lambda p: p.replace(" ", "+"),
    "between": lambda p: re.sub(r">(\d+)", r" BETWEEN 0 AND \1", p, count=1),
}

WAF_SIGS = {"cloudflare": ["cloudflare", "cf-ray"], "aws": ["awselb", "x-amzn"],
            "akamai": ["akamai", "reference #"], "imperva": ["incapsula", "imperva"]}

class Session:
    def __init__(self, proxy=None, ua=None, cookie=None, no_redirect=False, timeout=12):
        h = {"User-Agent": ua or random.choice(UAS)}
        if cookie: h["Cookie"] = cookie
        self.c = httpx.Client(proxy=proxy, timeout=timeout,
                              follow_redirects=not no_redirect, headers=h)
    def get(self, url, **kw): return self.c.get(url, **kw)
    def post(self, url, data=None, **kw): return self.c.post(url, data=data, **kw)

def detect_waf(resp):
    body = (resp.text + str(resp.headers)).lower()
    return [k for k, sigs in WAF_SIGS.items() if any(s in body for s in sigs)] or ["none detected"]

def extract_links(html):
    return sorted(set(re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', html)))

def selftest():
    assert balance("a b", "plus") == "a+b"
    assert TAMPERS["space2comment"]("UNION SELECT") == "UNION/**/SELECT"
    assert "/x" in extract_links('<a href="/x">1</a>')
    print("[selftest] core OK ✔")