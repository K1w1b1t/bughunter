# Hybrid Stack Strategy

## Core Decision
- Python is the central orchestrator.
- High-volume execution uses fast external tools (primarily Go binaries).
- Node.js is used where browser/JS automation is required.

## Practical Stack by Phase

### Recon
- Languages: Python, Go, Bash
- Tools: `subfinder`, `amass`, `assetfinder`, `httpx`, `dnsx`, `waybackurls`, `gau`, `jq`
- Rule: keep Python as controller and call tools via subprocess.

### Enumeration / Crawling
- Languages: Python, Go, Node.js
- Tools: `katana`, `hakrawler`, `gospider`
- Libraries: `Scrapy`, `BeautifulSoup`
- Rule: for JS-heavy apps, use browser automation.

### Fuzzing
- Default: `ffuf` for high-volume scenarios.
- Alternatives: `gobuster`, `wfuzz`, `dirsearch`.
- Rule: use Python for custom decision logic and specialized workflows.

### Automation / Login / JS Flows
- Tools: `Playwright`, `Puppeteer`, `Selenium`
- Rule: prioritize Playwright for modern SPAs.

### Vulnerability Testing
- Baseline sweep: `nuclei`
- Validation/PoC support: `sqlmap`, `XSStrike`, `dalfox`, `commix`
- Rule: use broad scanners for signal generation and targeted scripts for proof.

## Pipeline Standard
1. Scope-guard targets.
2. Run recon and probe.
3. Enumerate and crawl paths.
4. Run controlled fuzzing.
5. Run vulnerability scans.
6. Validate manually, enforce quality gate, then report.
