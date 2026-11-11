cat > README.md << 'EOF'

\# 🛡️ ReconX v3.0



> AI-powered web penetration testing toolkit — CLI + Web GUI + AI Mentor



!\[Python](https://img.shields.io/badge/python-3.10+-blue)

!\[License](https://img.shields.io/badge/license-MIT-green)

!\[Version](https://img.shields.io/badge/version-3.0.0-orange)



\## ✨ Features



| Module | Description |

|--------|-------------|

| `sqli` | Union, error-based, xpath, double-query, dump — MySQL/PostgreSQL/MSSQL |

| `bypass` | WAF tampers, order-by/union bypass, URL balancer |

| `lfi` | Local File Inclusion + php://filter detection |

| `xss` | Reflected XSS probe suite |

| `cmdi` | Command injection (RCE) detection |

| `ssrf` | SSRF + cloud metadata probing |

| `admin` | Admin panel finder |

| `dirb` | Sensitive file/dir scanner |

| `authbypass` | Login bypass payload testing |

| `ai` | 🤖 Built-in AI mentor (Together API) — explains bugs \& tools |

| `checklist` | OWASP WSTG 12-area methodology |



\## 📦 Install



```bash

git clone https://github.com/darkvict0r/reconx.git

cd reconx

python3 -m venv venv \&\& source venv/bin/activate

pip install -r requirements.txt

export TOGETHER\_API\_KEY="your-key"   # optional, AI features ke liye

