# 🛡️ SOCTI Toolkit

A comprehensive **Security Operations Centre (SOC) toolkit** for Windows, combining IoC reputation scoring, asset parsing, DNS enrichment, Active Directory auditing, patch management analysis, and more — all in a unified GUI or CLI interface.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## ✨ Modules

### 1. SepRep — Separator + Reputation Engine
Dual-mode tool for normalising and reputation-checking Indicators of Compromise (IoCs).
- **Normalisation**: Cleans raw text (logs, emails, CSVs) into structured lists of IPs, domains, or hashes.
- **VirusTotal Integration**: Detection ratios, community scores, threat categories.
- **AbuseIPDB Integration**: IP abuse confidence, country, and ISP.
- **Colour-coded output**: Red = Malicious, Green = Safe.
- **Auto-export**: CSV reports with verdicts and threat details.

### 2. HostSplit — Asset Extraction & DNS
Three-panel tool for parsing mixed security logs.
- **Smart classification**: Extracts and classifies tokens as `IPv4`, `Hostname`, or `Derived (Host@IP)`.
- **Bulk DNS Lookup**: Forward (Hostname → IP) and Reverse (IP → Hostname) — silent background execution.
- **Export**: JSON or CSV.

### 3. Asset Comparator
Compare two asset datasets to find discrepancies instantly.
- Set operations: Common, Unique to A, Unique to B.
- Input normalisation: whitespace trimming, deduplication.
- Export: CSV or JSON.

### 4. IT Audit Engine (`itaudit_engine/`)
Active Directory domain admission review pipeline.
- Ingests multiple CSV sources (Hosts lists, AD joined systems).
- Correlation and diagnostics across data sources.
- Generates formatted `.docx` / `.xlsx` audit reports.

### 5. I-Mrk — Intelligent Markdown Reporter
Converts raw documents (`.txt`, `.docx`, `.xlsx`) to structured Markdown using an LLM.
- LLM-powered chunking and classification.
- Multiple export formats.

### 6. Additional Engines
| Engine | Description |
|--------|-------------|
| `ad_engine.py` | Active Directory LDAP query builder |
| `dns_engine.py` | DNS resolution and enrichment |
| `ping_engine.py` | Bulk ICMP ping sweep |
| `drive_audit_engine.py` | Drive/storage audit |
| `pm_engine.py` | Patch management log analysis |
| `pm_email_dispatcher.py` | Email dispatch for PM reports |
| `reputation.py` | Standalone IoC reputation checker |
| `vpm_policy_reviewer.py` | VPM policy review automation |
| `asset_compliance_checker.py` | Asset compliance validation |

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|-----------|
| Language | Python 3.10+ |
| GUI | Tkinter |
| Data processing | Pandas, OpenPyXL |
| Document generation | python-docx |
| API integration | requests (VirusTotal, AbuseIPDB) |
| Packaging | PyInstaller |
| Testing | pytest |

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/OdigieDavidIdemudia/SOCTI-Toolkit.git
cd SOCTI-Toolkit
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure settings

```bash
cp settings.json.example settings.json
```

Edit `settings.json` or use the **API Settings** button in the GUI to add:
- `virustotal_api_key`
- `abuseipdb_api_key`
- Proxy settings (for corporate environments)

---

## 🖥️ Usage

### GUI Mode

```bash
python gui.py
```

**Tabs:**
- **SepRep**: Paste IoCs → Select VirusTotal or AbuseIPDB → Results are colour-coded and auto-exported to CSV.
- **HostSplit**: Paste mixed logs (e.g. `ServerA (192.168.1.5)`) → Split → DNS Lookup.
- **Asset Comparator**: Upload files or paste lists to compare and find discrepancies.

### CLI Mode

```bash
# Normalise a list of IPs and separate with commas
python main.py "ip1 ip2 ip3" --sep ","
# Output: ip1,ip2,ip3
```

### IT Audit

```bash
python -m itaudit_engine.main
```

---

## 📦 Building a Portable Executable

```bash
# Full GUI build
pyinstaller SOCTI_Toolkit.spec

# Lightweight SepX build
pyinstaller --onefile --windowed --name SepX gui.py
```

The executable lands in `dist/`.

---

## 🔒 Corporate Proxy Support

Configure authenticated HTTP/HTTPS proxy settings in `settings.json`:

```json
{
  "proxy": {
    "http": "http://user:pass@proxy.corp:8080",
    "https": "http://user:pass@proxy.corp:8080"
  },
  "ssl_verify": false
}
```

Or configure via the **Proxy Settings** modal in the GUI.

---

## 📁 Project Structure

```
SOCTI-Toolkit/
├── gui.py                      # Main GUI entry point (Tkinter)
├── main.py                     # CLI entry point (SepRep normaliser)
├── seprep.py                   # SepRep engine
├── comparator.py               # Asset comparator engine
├── dns_engine.py               # DNS lookup engine
├── ad_engine.py                # Active Directory engine
├── reputation.py               # IoC reputation checker
├── pm_engine.py                # Patch management engine
├── itaudit_engine/             # IT audit pipeline
│   ├── main.py
│   ├── ingestion.py
│   ├── correlation.py
│   ├── normalization.py
│   ├── diagnostics.py
│   └── reporting.py
├── I-Mrk/                      # Intelligent Markdown Reporter
│   └── imrk/
├── tests/                      # pytest test suite
├── settings.json.example
├── requirements.txt
└── screenshots/
```

---

## 📸 Screenshots

![SOCTI Toolkit GUI](screenshots/sepx_gui.png)

---

## 📄 License

MIT License
