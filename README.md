# 🛡️ 10blackfingers

> **AI-Powered Web Vulnerability Scanner for ISEF 2026**

An integrated platform for automated web vulnerability discovery using open-source tools and AI.

---

## 🎯 Features

- **4-Stage Scanning Pipeline**: Reconnaissance, Known Vulnerabilities, Zero-Day Detection, Remediation & Threat Profiling.
- **30+ Security Tools**: Nuclei, OWASP ZAP, SQLMap, Nmap, and more.
- **AI-Powered Analysis**: Automated remediation reports and threat actor attribution.
- **PWA Interface**: Installable as a mobile/desktop app.
- **Fully Cloud-Based**: No local installation required.

---

## 🏗️ Architecture

~~~
┌─────────────────────────────────────────────────────────┐
│  User (Browser)                                         │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  Frontend (Vercel)                                      │
│  - HTML/CSS/JavaScript                                  │
│  - PWA Manifest                                         │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  Backend (Render)                                       │
│  - FastAPI                                              │
│  - Request handling and orchestration                   │
└──────┬──────────────────────────┬───────────────────────┘
       │                          │
       ▼                          ▼
┌──────────────┐          ┌──────────────────────┐
│ GitHub       │          │ Supabase             │
│ Actions      │          │ - Database           │
│ - Nuclei     │          │ - Result storage     │
│ - ZAP        │          └──────────────────────┘
│ - SQLMap     │
│ - etc.       │          ┌──────────────────────┐
└──────────────┘          │ Modal.com            │
                          │ - AI Analysis        │
                          │ - Remediation reports│
                          └──────────────────────┘
~~~

---

## 🔧 Tech Stack

| Component | Technology |
|-----------|------------|
| Frontend | HTML, CSS, JavaScript (Vanilla) |
| Backend | Python 3.11 + FastAPI |
| Database | Supabase (PostgreSQL) |
| Frontend Hosting | Vercel |
| Backend Hosting | Render |
| Heavy Scanning | GitHub Actions |
| AI Analysis | Modal.com |
| Security Tools | Nuclei, ZAP, SQLMap, Nmap, etc. |

---

## 📚 Scanning Phases

### Phase 1: Reconnaissance
8 tools to map the target infrastructure:
- Wappalyzergo, ServerSpy, Subfinder, Amass, Katana, Nmap, WAFW00F, CipherRun

### Phase 2: Known Vulnerabilities
8 tools to detect common vulnerabilities:
- Nuclei, OWASP ZAP, Nikto, SQLMap, Wapiti, AIPTX, S2N, Deep Eye

### Phase 3: Zero-Day Detection
7 techniques to uncover unknown vulnerabilities:
- Isolation Forest, SnortML+, LlamaIDS, AutoWAFuzzer, DeepRadar, CANalyze-AI, GANs

### Phase 4: Remediation & Threat Profiling
7 tools for threat analysis:
- AIPTX, LogSage, LLMSecConfig, MITRE ATT&CK, veCTIon, Horizon3, APT Profiler

---

## ⚖️ Ethical Considerations

- The platform requires **written authorization** from the target owner before scanning.
- Scanning is strictly limited to the authorized scope.
- Rate limiting is enforced to prevent any DoS-like impact.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

Developed by the **10blackfingers** team for ISEF 2026.

---

**© 2026 10blackfingers. All rights reserved.**
