import argparse
from .core import selftest as core_st
from .sqli import run as sqli_run
from . import modules
from .checklist import show as show_checklist
from .ai import ask, explain_tool, triage

def main():
    p = argparse.ArgumentParser(prog="reconx", description="ReconX v3.0 FINAL — full web pentest toolkit + AI mentor")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest"); sub.add_parser("checklist")

    s = sub.add_parser("sqli")
    for f in ["--url", "--param"]: s.add_argument(f, required=True)
    s.add_argument("--method", default="GET", choices=["GET", "POST"])
    s.add_argument("--data", default=""); s.add_argument("--cookie"); s.add_argument("--proxy")
    s.add_argument("--ua"); s.add_argument("--no-redirect", action="store_true")
    s.add_argument("--tamper", default="plain", choices=["plain", "plus", "encode", "double", "comment",
                   "space2comment", "randomcase", "eq2like", "space2plus", "between"])
    s.add_argument("--dbms", default="mysql", choices=["mysql", "pgsql", "mssql"])
    s.add_argument("--replace", action="append", default=[]); s.add_argument("--fprint", action="append", default=[])
    s.add_argument("--tables", action="store_true"); s.add_argument("--columns")
    s.add_argument("--dump"); s.add_argument("--limit", type=int, default=10)
    s.add_argument("--privs", action="store_true"); s.add_argument("--ai", action="store_true")

    for name, req in [("lfi", ["--url", "--param"]), ("xss", ["--url", "--param"]),
                      ("cmdi", ["--url", "--param"]), ("ssrf", ["--url", "--param"]),
                      ("admin", ["--url"]), ("dirb", ["--url"]),
                      ("links", ["--url"]), ("upload", ["--url"])]:
        sp = sub.add_parser(name)
        for r in req: sp.add_argument(r, required=True)
        sp.add_argument("--cookie"); sp.add_argument("--proxy")
        if name == "upload": sp.add_argument("--field", default="file")

    ab = sub.add_parser("authbypass"); ab.add_argument("--url", required=True)
    ab.add_argument("--user-field", default="username"); ab.add_argument("--pass-field", default="password")
    ab.add_argument("--data", default=""); ab.add_argument("--cookie"); ab.add_argument("--proxy")
    e = sub.add_parser("explain"); e.add_argument("question", nargs="+")
    t = sub.add_parser("tool"); t.add_argument("name")
    args = p.parse_args()

    if args.cmd == "selftest": core_st(); return
    if args.cmd == "checklist": show_checklist(); return
    if args.cmd == "sqli": sqli_run(args); return
    M = {"lfi": modules.lfi, "xss": modules.xss, "cmdi": modules.cmdi, "ssrf": modules.ssrf,
         "admin": modules.admin_finder, "dirb": modules.dirb, "links": modules.links}
    if args.cmd in M:
        fn = M[args.cmd]
        out = fn(args.url, args.param) if args.cmd in ("lfi", "xss", "cmdi", "ssrf") else fn(args.url, args.cookie, args.proxy)
        print(f"[{args.cmd.upper()}]:", out or "kuch nahi mila"); return
    if args.cmd == "upload": print(modules.upload_test(args.url, args.field, args.cookie, args.proxy)); return
    if args.cmd == "authbypass":
        extra = dict(kv.split("=", 1) for kv in args.data.split("&")) if args.data else None
        print("[AuthBypass]:", modules.auth_bypass(args.url, args.user_field, args.pass_field, extra, args.cookie, args.proxy) or "kuch nahi mila"); return
    if args.cmd == "explain": print(ask(" ".join(args.question))); return
    if args.cmd == "tool": print(explain_tool(args.name)); return

if __name__ == "__main__": main()