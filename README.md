# ReconX v3.0 - AI-Powered Cybersecurity Web Reconnaissance Platform

ReconX is a premium, enterprise-grade reconnaissance and information-gathering platform designed for security researchers, penetration testers, SOC analysts, and bug bounty hunters. It combines real-time network intelligence, protocol diagnostics, visual risk metrics, and automated AI security advisories into a sleek glassmorphic dashboard.

---

## Key Features

- **Split-Screen Cyber Intelligence Hub**: HackerRank-inspired layout balancing visual scanning feedback with real-time logging output.
- **Multiprocessing Diagnostic Sweep Engine**:
  - **WHOIS Query**: Dual-library wrapper (`whois` / `python-whois`) with DNS SOA/NS fallbacks.
  - **DNS Enumeration**: Resolves A, AAAA, MX, TXT, and NS records.
  - **IP Intelligence**: Resolves server geolocations, organization details, and network routing.
  - **SSL/TLS handshake validation**: Assesses certificate validity, encryption protocols, and expiry.
  - **HTTP Headers analyzer**: Validates presence of security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
  - **Clickjacking Framing test**: Sandbox testing with resolved secure URL previews.
  - **Robots.txt & Sitemap discovery**: Passive mapping of crawl rules and sitemap listings.
  - **Technology Fingerprinting**: Passively fingerprint stacks and WAF/CDN guards (Cloudflare, Akamai, AWS CloudFront).
- **Tabbed Results Visualization**: Dynamic panel separation with interactive visual charts (Risk Score Gauge, Threat Heatmap).
- **AI Security Advisor**: Local context-driven mitigation advisories with MITRE ATT&CK & OWASP mapping.
- **Server-Side Exporter**: Instantly download reports in JSON, TXT, and CSV format.
- **OAuth Authentication Integration**: Seamless mock OAuth options and session-bound scan history database tracking.
- **Premium Themes System**: Integrated support for High-Contrast Light Theme and Cyberpunk Dark Theme with auto-refresh canvas charts.

---

## Project Structure

```
├── app.py               # Flask Web Application & Event Stream (SSE) Router
├── scanner.py           # Core Security Scan Engine (DNS, WHOIS, SSL, Headers, Tech)
├── database.py          # SQLite Schema Operations & Persistent Scan Logs
├── test_reconx.py       # Comprehensive Backend Test Suite
├── requirements.txt     # Python Dependencies
├── templates/
│   ├── base.html        # Glassmorphic Base Template & Global Toast system
│   ├── login.html       # Split-Screen Premium Authentication Page
│   ├── dashboard.html   # Main Diagnostic Sweep Panel & Tabbed Scan Results
│   ├── scan_detail.html # Static Historical Scan Detail & Iframe Previewer
│   └── admin.html       # Operator Admin Dashboard & Announcements Panel
└── static/
    ├── css/
    │   └── style.css    # Responsive High-Contrast Theme Stylesheet
    └── js/
        └── main.js      # SSE Handler, Dynamic Charts Renderer, UI Coordinators
```

---

## Installation & Setup

### 1. Clone the Repository & Initialize Environment
```bash
git clone <repository-url>
cd morsevisiom
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Initialize & Start the Platform
```bash
python app.py
```
Open [http://localhost:5000](http://localhost:5000) in your web browser.

---

## Running Test Suite

ReconX includes a comprehensive unit testing suite verifying authentication gates, WHOIS queries, SSL handlers, headers checking, and database operations.

To execute the test suite:
```bash
python -m unittest test_reconx.py
```

---

## License

This software is developed for ethical penetration testing and security assessment. Use responsibly under local laws and guidelines.
