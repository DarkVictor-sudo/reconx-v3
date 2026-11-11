"""OWASP WSTG v4.2 ke 12 areas — pentest methodology guide [research-based]"""
WSTG = {
 "1. Info Gathering": "robots.txt, fingerprints, entry points, admin panels, source comments",
 "2. Config Mgmt": "backup files, dir listing, HTTP methods, TLS, subdomain takeover",
 "3. Identity Mgmt": "role definitions, username enumeration, predictable usernames",
 "4. Authentication": "default creds, lockout, bypass, reset flaws, MFA, brute force",
 "5. Authorization": "IDOR, privilege escalation, forced browsing, SSRF, path traversal",
 "6. Session Mgmt": "cookie flags, fixation, CSRF, timeout, logout, token in URL",
 "7. Input Validation": "SQLi, NoSQLi, XSS, CMDi, LDAPi, SSTI, request smuggling",
 "8. Error Handling": "stack traces, verbose errors, fail-open checks",
 "9. Crypto": "weak TLS, unsalted hashes, padding oracle, sensitive data in URLs",
 "10. Business Logic": "price tampering, step skip, race conditions, coupon abuse, upload types",
 "11. Client-side": "DOM XSS, open redirects, CORS, clickjacking, WebSocket origin",
 "12. API Testing": "object-level authz, GraphQL introspection, mass assignment, versioning",
}

def show():
    print("\n=== OWASP WSTG 12-Area Checklist (ReconX Methodology) ===\n")
    for k, v in WSTG.items(): print(f"  {k:22} → {v}")
    print("\n[*] Har area pe manually test karo, findings log karo, report banao.")