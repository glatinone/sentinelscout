# 🛡️ SentinelScout

> Multi-source OSINT aggregator for threat intelligence. Fetch IOCs from VirusTotal, AlienVault OTX, Shodan, CVE feeds, and GitHub — then let AI analyze and correlate them.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Features

- 🔍 **Multi-source scraping** — VirusTotal, AlienVault OTX, Shodan, NVD CVE, GitHub
- 🤖 **AI-powered analysis** — Correlates IOCs, scores threat severity
- ⚡ **Async concurrent fetching** — All sources queried in parallel
- 📊 **Clean CLI dashboard** — Color-coded severity, grouped output
- 🔧 **Configurable** — API keys via `.env`, easy to extend
- 🐳 **Docker ready** — Run anywhere in seconds

## Installation

```bash
pip install sentinelscout
```

Or from source:

```bash
git clone https://github.com/glatinone/sentinelscout.git
cd sentinelscout
pip install -e .
```

## Quick Start

```bash
# Query a domain across all sources
sentinelscout query example.com

# Query a specific source
sentinelscout query 8.8.8.8 --source shodan

# Query CVE data
sentinelscout cve --cve CVE-2024-21762

# List available sources
sentinelscout sources

# Set API keys
sentinelscout config --set VIRUSTOTAL_API_KEY=your_key
```

## Configuration

Create a `.env` file or set environment variables:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ALIENVAULT_API_KEY=your_alienvault_api_key
SHODAN_API_KEY=your_shodan_api_key
OPENAI_API_KEY=your_openai_api_key  # Optional, for AI analysis
```

## Architecture

```
sentinelscout/
├── cli.py              # CLI entrypoint (Typer)
├── analyzer.py         # AI correlation engine
├── config.py           # Config & .env loader
├── sources/
│   ├── virustotal.py   # VirusTotal API client
│   ├── alienvault.py   # AlienVault OTX client
│   ├── shodan.py       # Shodan API client
│   ├── cve.py          # NVD CVE feed scraper
│   └── github.py       # GitHub security advisories
└── models.py           # IOC data models
```

## Supported Sources

| Source | Type | API Required | Free Tier |
|--------|------|-------------|-----------|
| VirusTotal | Domain/IP/Hash | Yes | 500 req/day |
| AlienVault OTX | IP/Domain/Hash | Yes | 10k pulses/day |
| Shodan | IP/Port | Yes | 100 queries/month |
| NVD CVE | Vulnerabilities | No | Unlimited |
| GitHub Advisories | Vulnerabilities | No | Unlimited |

## Demo

```
$ sentinelscout query malicious-actor.xyz

🛡️ SentinelScout — IOC Lookup
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Query: malicious-actor.xyz
Mode:  full (all sources)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 VIRUSTOTAL       [HIGH RISK]
  └─ 67/94 engines flagged
  └─ Categories: malware, phishing
  └─ Last analyzed: 2 hours ago

🟡 ALIENVAULT OTX   [SUSPICIOUS]
  └─ 3 pulse(s) found
  └─ Tags: [apt] [phishing] [2024]
  └─ Related IPs: 185.220.xxx.xxx, 91.132.xxx.xxx

🟢 SHODAN           [INFO]
  └─ 4 open ports detected
  └─ Services: HTTP (80), HTTPS (443), SSH (22)

🟢 NVD CVE           [LOW RISK]
  └─ No known CVEs for this domain

🟢 GITHUB ADV        [LOW RISK]
  └─ No advisories found

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 AI Analysis:
"Multiple threat intelligence sources confirm this
domain is actively used for phishing campaigns.
Affiliated with multiple C2 IPs. Treat as blocked."
Threat Score: 87/100 🔴 CRITICAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Extending Sources

Adding a new source is simple:

```python
from sentinelscout.sources import BaseSource

class MySource(BaseSource):
    name = "mysource"
    priority = 2

    async def query(self, indicator: str) -> IOCResult:
        # Your scraping logic here
        return IOCResult(...)
```

## License

MIT © [glatinone](https://github.com/glatinone)