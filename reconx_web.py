from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from reconx import modules
from reconx.ai import ask
from reconx.checklist import WSTG

app = FastAPI(title="ReconX v3.0 FINAL")
PAGE = """<!doctype html><html><head><title>ReconX v3.0</title><style>
body{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:2rem}
input,button{padding:.5rem;background:#161b22;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;font-family:monospace}
button{cursor:pointer;background:#238636;margin:2px}h1{color:#58a6ff}
#out{white-space:pre-wrap;background:#161b22;padding:1rem;border-radius:8px;margin-top:1rem;min-height:150px}
</style></head><body><h1>🛡️ ReconX v3.0 FINAL — Web Pentest + AI</h1>
<input id="u" placeholder="http://localhost/target.php" size="42">
<input id="p" placeholder="param" size="10">
<div>
<button onclick="go('lfi')">LFI</button><button onclick="go('xss')">XSS</button>
<button onclick="go('cmdi')">RCE</button><button onclick="go('ssrf')">SSRF</button>
<button onclick="go('admin')">Admin</button><button onclick="go('dirb')">DirB</button>
<button onclick="go('links')">Links</button>
</div>
<input id="q" placeholder="AI se kuch bhi pucho..." size="52">
<button onclick="aiq()">🤖 Ask ReconX AI</button>
<div id="out">Ready.</div>
<script>
async function go(t){const u=document.getElementById('u').value,p=document.getElementById('p').value;
document.getElementById('out').textContent='Running '+t+'...';
const r=await fetch(`/api/run?tool=${t}&url=${encodeURIComponent(u)}&param=${p}`);
document.getElementById('out').textContent=(await r.json()).out;}
async function aiq(){const q=document.getElementById('q').value;
document.getElementById('out').textContent='🤖 AI soch raha hai...';
const r=await fetch(`/api/ai?q=${encodeURIComponent(q)}`);
document.getElementById('out').textContent=(await r.json()).out;}
</script></body></html>"""

@app.get("/", response_class=HTMLResponse)
def home(): return PAGE

@app.get("/api/run")
def run(tool: str, url: str, param: str = "id"):
    fns = {"lfi": lambda: modules.lfi(url, param), "xss": lambda: modules.xss(url, param),
           "cmdi": lambda: modules.cmdi(url, param), "ssrf": lambda: modules.ssrf(url, param),
           "admin": lambda: modules.admin_finder(url), "dirb": lambda: modules.dirb(url),
           "links": lambda: modules.links(url)}
    return {"out": str(fns.get(tool, lambda: "unknown")())}

@app.get("/api/ai")
def ai(q: str): return {"out": ask(q)}

# Run: uvicorn reconx_web:app --reload