# Run: mitmdump -s ai_watch.py -p 8080
# Browser proxy → 127.0.0.1:8080 → AI har 10 requests pe hints dega!
from mitmproxy import http
from reconx.ai import ask
LOG = []
def response(flow: http.HTTPFlow):
    LOG.append(f"{flow.request.method} {flow.request.pretty_url} -> {flow.response.status_code}")
    if len(LOG) % 10 == 0:
        print("\n=== ReconX AI ===")
        print(ask("Researcher ne ye requests bheji:\n" + "\n".join(LOG[-10:]) +
                  "\nKya test karu? OWASP WSTG ke hisaab se 3 short hints do."))