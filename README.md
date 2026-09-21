# 🛡️ AI-Assisted Phishing Email Analyzer

An evidence-driven phishing email investigation platform designed as a SOC Analyst portfolio project.

The application analyzes `.eml` email samples through multiple security investigation stages including email parsing, header analysis, content analysis, URL analysis, VirusTotal reputation checks, attachment hashing, MITRE ATT&CK mapping, risk scoring, and AI-assisted analyst reporting.

The project provides a Streamlit dashboard for conducting the investigation and reviewing the results.

---

## 🎯 Project Overview

Phishing emails are a common initial access technique used by attackers to deceive users into clicking malicious links, opening attachments, or revealing credentials.

This project simulates a SOC analyst workflow for investigating suspicious emails.

Instead of relying entirely on an AI model to classify an email, the system follows an evidence-first approach:

```text
                ┌─────────────────────┐
                │   .EML Email Sample │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │    Email Parser     │
                └──────────┬──────────┘
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
        Header Analysis  Content      URL Analysis
             │           Analysis          │
             │             │                │
             └─────────────┼────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
      Attachment Analysis          VirusTotal
             │                           │
             └─────────────┬─────────────┘
                           ▼
                  MITRE ATT&CK Mapping
                           │
                           ▼
                    Risk Assessment
                           │
                           ▼
                   AI Analyst Report
                           │
                           ▼
                 Streamlit Dashboard
```

The AI component receives structured investigation evidence rather than blindly analyzing the raw email.

---

# 🔍 Features

## 📧 Email Parsing

Extracts important email metadata including:

- From
- To
- Subject
- Date
- Reply-To
- Return-Path
- Message-ID
- Plain-text body
- HTML body

---

## 📨 Header Analysis

Checks email headers for suspicious indicators such as:

- Reply-To mismatch
- Return-Path mismatch
- SPF failure
- DKIM failure
- Missing DKIM
- DMARC failure
- Received headers

Example:

```text
From:
support@microsoft.com

Reply-To:
security-alert@evil-example.com

Return-Path:
security-alert@evil-example.com
```

The analyzer identifies the domain mismatch as investigation evidence.

---

# 📝 Content Analysis

The email body is examined for common phishing indicators including:

- Urgency language
- Account verification requests
- Credential-related language
- Threat or account suspension language
- Payment-related language
- Calls to action

Content findings are represented as structured evidence before being passed to the AI reporting layer.

---

# 🔗 URL Analysis

URLs are extracted from both:

- Plain-text email bodies
- HTML email content

Static URL analysis checks for indicators such as:

- IP-based URLs
- HTTP instead of HTTPS
- Suspicious URL keywords
- Login-related keywords
- Account verification keywords

Example:

```text
https://evil-example.com/login
```

The system records the URL as an observable indicator and performs additional reputation checking.

---

# 🦠 VirusTotal Integration

The project integrates with the VirusTotal API to check:

- URL reputation
- File hash reputation

The analyzer records:

```text
Malicious detections
Suspicious detections
Harmless detections
Undetected results
```

Important:

> A zero-detection VirusTotal result does not prove that an indicator is safe.

VirusTotal results are treated as one source of evidence rather than absolute proof.

---

# 📎 Attachment Analysis

Email attachments are extracted without executing them.

For each attachment the system records:

- Filename
- MIME/content type
- File size
- SHA-256 hash

The SHA-256 hash can then be checked against VirusTotal.

The project deliberately performs static analysis rather than executing potentially malicious files.

---

# 🎯 MITRE ATT&CK Mapping

Observed phishing-related evidence is mapped to relevant MITRE ATT&CK techniques.

Examples include:

```text
T1566
Phishing

T1566.001
Phishing: Spearphishing Attachment

T1566.002
Phishing: Spearphishing Link
```

Mappings are based on observed evidence and include confidence information.

The project does not treat a technique mapping as proof of attacker intent.

---

# 📊 Risk Engine

A lightweight evidence-based risk engine calculates a prioritization score from observed findings.

Example scoring categories include:

```text
Info       → 0 points
Low        → 5 points
Medium     → 10 points
High       → 20 points
Critical   → 30 points
```

Additional points can be assigned for:

- Malicious VirusTotal URL detections
- Suspicious VirusTotal URL detections
- Malicious file hash detections
- Suspicious file hash detections

The final score is capped at 100.

Risk levels:

```text
0–24     → Low
25–49    → Suspicious
50–74    → High
75–100   → Critical
```

### Important

The risk score is a **prioritization mechanism**, not a probability that an email is malicious.

---

# 🤖 AI SOC Analyst

The AI component generates a structured SOC-style investigation report using the collected evidence.

The AI report includes:

- Verdict
- Confidence
- Executive summary
- Key findings
- Observed IOCs
- MITRE ATT&CK information
- Recommended analyst actions
- Analyst notes

The AI is instructed to:

- Use only supplied evidence
- Avoid inventing IOCs
- Avoid inventing MITRE techniques
- Distinguish evidence from interpretation
- Mention uncertainty
- Avoid treating zero VirusTotal detections as proof of safety
- Treat the risk score as a prioritization score rather than a probability

This creates an **evidence-first AI workflow** rather than an AI-only phishing classifier.

---

# 🖥️ Streamlit SOC Dashboard

The project includes a Streamlit dashboard for interacting with the analyzer.

The dashboard provides:

### Investigation Overview

- Risk score
- Risk level
- AI verdict
- IOC count
- MITRE technique count

### Email Information

- Sender
- Recipient
- Subject
- Date
- Reply-To

### Investigation Tabs

```text
🤖 AI Assessment
📨 Headers
📝 Content
🔗 URLs
📎 Attachments
🎯 MITRE ATT&CK
📊 Risk Evidence
```

### Export

The complete investigation can be exported as:

```text
phishing_investigation_report.json
```

---

# 🏗️ Project Architecture

```text
AI-Phishing-Email-Analyzer/
│
├── analyzer/
│   ├── __init__.py
│   ├── email_parser.py
│   ├── header_analyzer.py
│   ├── content_analyzer.py
│   ├── url_analyzer.py
│   ├── virustotal.py
│   ├── attachment_analyzer.py
│   ├── mitre_mapper.py
│   ├── risk_engine.py
│   ├── investigator.py
│   ├── ai_report.py
│   └── save_report.py
│
├── samples/
│   ├── test_email.eml
│   └── phishing/
│       ├── test_phishing.eml
│       └── test_attachment.eml
│
├── tests/
│   ├── __init__.py
│   ├── test_parser.py
│   ├── test_headers.py
│   ├── test_phishing_headers.py
│   ├── test_urls.py
│   ├── test_virustotal.py
│   ├── test_url_reputation.py
│   ├── test_attachments.py
│   ├── test_file_hash.py
│   ├── test_mitre_mapper.py
│   ├── test_risk_engine.py
│   ├── test_investigator.py
│   └── test_ai_report.py
│
├── reports/
│   └── ai_analysis_report.json
│
├── app.py
├── requirements.txt
├── .gitignore
├── .env
└── README.md
```

> `.env` and other sensitive files should not be committed to GitHub.

---

# ⚙️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core development |
| Streamlit | SOC dashboard |
| Python Email Library | `.eml` parsing |
| BeautifulSoup | HTML email analysis |
| Requests | API communication |
| VirusTotal API | Threat intelligence |
| OpenAI API | AI-assisted reporting |
| MITRE ATT&CK | Threat technique mapping |
| python-dotenv | Environment variable management |
| Git/GitHub | Version control |

---

# 🚀 Installation

## 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/AI-Phishing-Email-Analyzer.git
```

Move into the project:

```bash
cd AI-Phishing-Email-Analyzer
```

---

## 2. Create a virtual environment

Windows:

```bash
python -m venv venv
```

Activate:

```bash
venv\Scripts\activate
```

---

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

# 🔐 API Configuration

Create a `.env` file in the project root:

```text
VT_API_KEY=your_virustotal_api_key
OPENAI_API_KEY=your_openai_api_key
```

Never commit the `.env` file.

The `.gitignore` should contain:

```text
venv/
.env
__pycache__/
*.pyc
```

---

# ▶️ Running the Dashboard

Start Streamlit:

```bash
python -m streamlit run app.py
```

The dashboard will open locally.

Upload an `.eml` file through the sidebar and select:

```text
🔍 Analyze Email
```

The investigation pipeline will then execute.

---

# 🧪 Testing

Individual modules can be tested independently.

### Email parser

```bash
python -m tests.test_parser
```

### Header analysis

```bash
python -m tests.test_headers
```

### URL analysis

```bash
python -m tests.test_urls
```

### Attachment analysis

```bash
python -m tests.test_attachments
```

### MITRE mapping

```bash
python -m tests.test_mitre_mapper
```

### Risk engine

```bash
python -m tests.test_risk_engine
```

### Complete investigation

```bash
python -m tests.test_investigator
```

### AI report

```bash
python -m tests.test_ai_report
```

---

# 🧪 Test Data

The repository contains synthetic `.eml` files for testing.

The phishing sample intentionally contains indicators such as:

```text
Reply-To mismatch
Return-Path mismatch
SPF failure
DMARC failure
Missing DKIM
Suspicious login URL
```

The domains and indicators used in the demonstration samples are synthetic.

No real credentials or private email communications should be committed to this repository.

---

# 🔬 Example Investigation

A synthetic phishing email can produce evidence such as:

```text
Risk Score:
90 / 100

Risk Level:
Critical

AI Verdict:
Likely Phishing

Confidence:
High
```

Observed indicators may include:

```text
From:
support@microsoft.com

Reply-To:
security-alert@evil-example.com

Return-Path:
security-alert@evil-example.com

URL:
https://evil-example.com/login
```

The investigation can additionally identify:

```text
SPF failure
DMARC failure
DKIM missing
Reply-To mismatch
Return-Path mismatch
```

and map relevant evidence to MITRE ATT&CK.

> These results come from the project's synthetic test data and should not be interpreted as analysis of a real Microsoft email.

---

# 🧠 SOC Investigation Workflow

The project is designed around a simplified SOC analyst workflow:

```text
1. Receive suspicious email
            ↓
2. Parse email
            ↓
3. Inspect headers
            ↓
4. Analyze email content
            ↓
5. Extract URLs
            ↓
6. Check URL reputation
            ↓
7. Extract attachments
            ↓
8. Calculate file hashes
            ↓
9. Check file reputation
            ↓
10. Map observed evidence to MITRE ATT&CK
            ↓
11. Calculate investigation risk
            ↓
12. Generate analyst report
            ↓
13. Review recommended response actions
```

---

# 🛡️ Security Considerations

This project is intended for defensive cybersecurity education and SOC portfolio development.

The analyzer does not execute email attachments.

Suspicious URLs should not be opened directly during investigation.

Real-world investigations should use appropriate:

- Sandboxing
- Network isolation
- Endpoint telemetry
- SIEM data
- Mail gateway logs
- Proxy logs
- Identity logs
- Threat intelligence
- Organizational incident-response procedures

The project is a portfolio-level investigation platform and does not replace a production email security platform or SIEM.

---

# 📚 What I Learned

Through this project, I practiced:

- Email header analysis
- Phishing investigation
- IOC extraction
- URL analysis
- Threat intelligence integration
- VirusTotal API usage
- File hashing
- MITRE ATT&CK mapping
- Risk-based alert prioritization
- Structured security evidence
- AI-assisted SOC reporting
- Python modular application design
- API integration
- Environment-variable management
- Streamlit dashboard development
- Git/GitHub project organization

---

# 🚧 Future Improvements

Potential future improvements include:

- [ ] SPF/DKIM/DMARC parsing improvements
- [ ] Received-header path analysis
- [ ] Domain age / WHOIS enrichment
- [ ] DNS reputation analysis
- [ ] URL redirect-chain analysis
- [ ] HTML phishing-page analysis
- [ ] QR-code extraction
- [ ] More attachment file-type analysis
- [ ] YARA integration
- [ ] Automated IOC export
- [ ] PDF investigation reports
- [ ] SQLite investigation history
- [ ] Authentication/log correlation
- [ ] Improved MITRE evidence mapping
- [ ] Analyst case-management functionality
- [ ] Docker deployment
- [ ] Additional SOC dashboard visualizations

---

# 👩‍💻 Project Purpose

This project was developed as a cybersecurity portfolio project to demonstrate practical SOC Analyst skills in:

**Phishing Analysis → Threat Intelligence → IOC Analysis → MITRE ATT&CK → Risk Assessment → AI-Assisted Reporting**

The goal is to demonstrate how multiple investigation techniques can be combined into a single analyst workflow.

---

## 📜 License

This project is intended for educational and portfolio purposes.
