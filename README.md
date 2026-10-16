🛡️ 10blackfingers: Advanced Security Scanning & Penetration Testing PlatformISEF International Competition Project — A comprehensive, automated, enterprise-grade security assessment and penetration testing ecosystem powered by a decentralized GitHub Actions execution engine, Supabase serverless backend, FastAPI orchestration API, and an advanced responsive web frontend.📋 Table of ContentsOverviewPlatform ArchitectureThe 250+ Security Tools EngineProject StructurePrerequisites & Environment SetupLocal Development & DeploymentAPI Endpoints ReferenceSecurity & Safety ComplianceLicense📖 Overview10blackfingers is an elite, highly-scalable security scanning platform designed specifically for professional penetration testing, automated vulnerability assessment, and red-teaming simulations. Built for international competitive standards, it automates the execution of over 250 distinct security tools, utilities, binaries, and libraries across a robust cloud pipeline.The system operates via an asynchronous decoupled architecture:Frontend Dashboard: A high-performance, responsive web interface allowing users to input targets, grant legal consent, trigger scans, track real-time progress, and download professional reports.API Gateway (/api/index.py): A secure FastAPI backend handling target validation, IP-blocking against internal networks/SSRF attacks, session tracking, and GitHub Actions webhook dispatching.Execution Engine (security-scan.yml): A heavy-duty GitHub Actions runner that spins up an isolated Ubuntu container pre-installed with 250+ specialized security tools to execute full-spectrum reconnaissance, vulnerability scanning, and exploitation assessment.Database & Logging (Supabase): Secure cloud relational database storing scan metadata, target URLs, states, and detailed JSON evidence findings.🏗️ Platform Architecture┌────────────────────────┐         ┌────────────────────────┐         ┌────────────────────────┐
│                        │         │                        │         │                        │
│   Frontend Dashboard   │ ──────> │  FastAPI Gateway (API) │ ──────> │    Supabase Database   │
│   (HTML/JS/CSS/PWA)    │  (HTTP) │  (Vercel Serverless)   │  (REST) │  (Scans & Results Log) │
│                        │         │                        │         │                        │
└────────────────────────┘         └───────────┬────────────┘         └────────────────────────┘
                                               │
                                               │ (GitHub REST API Dispatch)
                                               v
                                   ┌────────────────────────┐
                                   │                        │
                                   │ GitHub Actions Engine  │
                                   │ (250+ Security Tools)  │
                                   │                        │
                                   └────────────────────────┘
🛠️ The 250+ Security Tools EngineThe scanning workflow (security-scan.yml) automatically provisions and executes a massive arsenal of security utilities categorized across major penetration testing phases:Network Scanning & Reconnaissance: nmap, masscan, rustscan, unicornscan, naabu, zmap, hping3, netcat, socat, dnsutils, whois, dnsrecon, fierce, dnsenum, amass, subfinder, assetfinder, findomain.Web Application Vulnerability Scanners: nikto, whatweb, wpscan, joomscan, droopescan, wapiti, skipfish, sqlmap, commix, xsser, wfuzz, ffuf, gobuster, dirb, dirsearch, feroxbuster, nuclei, dalfox, kiterunner.SSL / TLS & Cryptographic Analysis: sslscan, sslyze, testssl.sh, tlssled, wafw00f.Password Cracking & Brute Forcing: hydra, medusa, ncrack, patator, crowbar, john, hashcat, crunch, cewl, cupp, seclists.Active Directory, SMB & LDAP Assessment: smbclient, smbmap, enum4linux, rpcclient, ldap-utils, crackmapexec, netexec, impacket, bloodhound, kerbrute.Exploitation & Post-Exploitation Frameworks: metasploit-framework, searchsploit, routersploit, ysoserial, Rubeus, Seatbelt.Cloud & Container Security: checkov, prowler, scoutsuite, kube-hunter, kube-bench, trivy, grype, terrascan, tfsec, tflint.Secret & Code Auditing Detection: gitleaks, trufflehog, bandit, safety, semgrep, detect-secrets.📁 Project Structure10blackfingers/
├── .github/
│   └── workflows/
│       └── security-scan.yml       # Comprehensive 250+ tools GitHub Actions pipeline
├── .devcontainer/
│   └── devcontainer.json           # VS Code development container configuration
├── api/
│   ├── index.py                    # FastAPI application & report generators (TXT/HTML/PDF)
│   └── requirements.txt            # Python dependencies for API server
├── backend/
│   └── github_actions/
│       ├── render_spa.js           # Headless browser SPA rendering script
│       └── scanner.py              # Core orchestration parser & Supabase logger
├── frontend/
│   ├── index.html                  # Main user dashboard interface
│   ├── style.css                   # Modern responsive styling (RTL & Dark/Light mode)
│   ├── app.js                      # Frontend logic, API calls & state management
│   ├── manifest.json               # PWA Manifest configuration
│   └── sw.js                       # Service Worker for offline support
├── .env                            # Environment variables (Supabase & GitHub tokens)
├── .gitignore                      # Comprehensive git ignore rules
├── LICENSE                         # MIT Open Source License
├── requirements.txt                # Root requirements alias
└── vercel.json                     # Vercel deployment configuration
⚙️ Prerequisites & Environment SetupLocal RequirementsPython 3.11 or 3.12Node.js 20+Git & GitHub CLI (gh)Supabase Account & ProjectEnvironment Variables (.env)Create an .env file in the root directory with the following keys:SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-supabase-anon-key
SUPABASE_SERVICE_KEY=your-supabase-service-key
GITHUB_TOKEN=your-github-personal-access-token
GITHUB_REPO=your-username/10blackfingers
🚀 Local Development & Deployment1. Backend API Setupcd api
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn index:app --reload --port 8000
2. Frontend DevelopmentServe the frontend/ directory using any static file server (e.g., Live Server in VS Code or Python's HTTP server):cd frontend
python -m http.server 3000
3. Vercel DeploymentThe platform is fully optimized for Vercel deployment:vercel --prod
🔌 API Endpoints ReferenceEndpointMethodDescription/GETAPI Status and Version check/healthGETSystem health status and UTC timestamp/api/scanPOSTInitiates a target security scan and triggers GitHub Actions/api/scan/{scan_id}GETRetrieves scan metadata and vulnerability results/api/scansGETLists recent scans for a specific user session/api/scan/{scan_id}/report/txtGETDownloads security report in Plain Text format/api/scan/{scan_id}/report/htmlGETDownloads formatted HTML report with print/PDF support/api/scan/{scan_id}/report/pdfGETGenerates and downloads official PDF report via ReportLab🔒 Security & Safety ComplianceStrict SSRF Protection: The API blocks internal IPs (10.0.0.0/8, 192.168.0.0/16, 127.0.0.1, localhost, cloud metadata endpoints).Legal Consent Verification: Every scan request requires explicit affirmative user consent (consent=true) confirming authorization to scan the target asset.Secure Token Handling: All sensitive service keys and GitHub tokens are isolated using environment variables and server-side secret injection.📄 LicenseDistributed under the MIT License. See LICENSE for more information.