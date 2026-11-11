import os
import httpx

API = "https://api.together.xyz/v1/chat/completions"
MODEL = os.environ.get("RECONX_MODEL", "meta-llama/Llama-3.3-70B-Instruct-Turbo")

MENTOR = """You are ReconX AI - ek friendly security mentor jo Hinglish me samjhata hai.
- Findings/sawal simple language me explain karo: bug kya hai, kaise kaam karta hai, severity
- Har tool ka kaam batana jab user puche
- Sirf authorized testing (bug bounty scope, apna lab) ka context rakho
- Short, practical, step-by-step jawab do"""

def ask(question):
    key = os.environ.get("TOGETHER_API_KEY")
    if not key: return "[AI] Pehle: export TOGETHER_API_KEY='...'"
    try:
        r = httpx.post(API, headers={"Authorization": f"Bearer {key}"}, timeout=90, json={
            "model": MODEL,
            "messages": [{"role": "system", "content": MENTOR},
                         {"role": "user", "content": question}],
            "max_tokens": 700})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e: return f"[AI error] {e}"

def explain_tool(name):
    return ask(f"'{name}' pentest tool ka kya kaam hai? Kab use karte hain? 4-5 lines.")

def triage(findings):
    raw = "\n".join(str(f) for f in findings[:50])
    return ask(f"Ye recon findings hain:\n{raw}\n\nTop 3 promising findings + manual next steps + 1-line summary do.")