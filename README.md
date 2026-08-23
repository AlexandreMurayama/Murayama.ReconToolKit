# Murayama Recon Automation Toolkit

[English](README.md) | [Português (Brasil)](README-PT-BR.md)

A modular Python reconnaissance toolkit built for authorized cybersecurity assessments, security labs, and educational use.

The project combines **native reconnaissance components implemented in Python** with optional integrations for established security tools. Its goal is not to replace tools such as Nmap or Subfinder, but to demonstrate how reconnaissance stages can be automated, validated, correlated, and exported through a single workflow.

> **Authorized use only.** Run this toolkit only against systems you own or systems for which you have explicit permission to perform security testing.

## Features

### Native components

- DNS enumeration (`A`, `AAAA`, `MX`, `NS`, `TXT`)
- Concurrent subdomain enumeration using wordlists
- Wildcard DNS detection
- IPv4 and IPv6 subdomain resolution
- Concurrent TCP port scanning
- Common service identification
- HTTP/HTTPS reconnaissance
- HTML title extraction
- Basic technology fingerprinting
- HTTP security header analysis
- Subdomain result correlation and deduplication
- JSON report generation
- Verbose/debug logging
- Automated tests with pytest
- Installable command-line interface (`murayama-recon`)
- Custom MurayamaRecon terminal banner

### External enrichment

- **Nmap** — enriches ports discovered by the native scanner with service/product/version information
- **Subfinder** — adds passive subdomain discovery, followed by DNS validation performed by the toolkit

The native scanner remains responsible for initial port discovery. Nmap is an optional enrichment stage. Likewise, passive Subfinder results are treated as **candidates**, not confirmed assets, until they successfully resolve through DNS.

## Architecture

```text
                         Target
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
     DNS Enumeration   Subdomains      Native TCP Scan
                           |                |
                    +------+-------+        v
                    |              |       Nmap
                    v              v    Enrichment
                 Native        Subfinder
                    |              |
                    |        DNS Validation
                    |              |
                    +------+-------+
                           |
                           v
                  Merge / Deduplication
                           |
                           v
                  HTTP Reconnaissance
                           |
                  +--------+---------+
                  |                  |
                  v                  v
             Technologies      Security Headers
                           |
                           v
                      JSON Report
```

## Project structure

```text
Murayama.ReconToolKit/
├── recon/
│   ├── __init__.py
│   ├── app.py
│   ├── banner.py
│   ├── cli.py
│   ├── cli_entry.py
│   ├── dns.py
│   ├── http.py
│   ├── logger.py
│   ├── nmap.py
│   ├── output.py
│   ├── ports.py
│   ├── subdomains.py
│   ├── subfinder.py
│   └── technologies.py
├── tests/
├── wordlists/
│   └── subdomains.txt
├── output/
│   └── .gitkeep
├── pyproject.toml
├── requirements.txt
├── pytest.ini
├── README.md
└── README-PT-BR.md
```

## Requirements

- Python 3
- pip
- Nmap (optional, required only for `--nmap`)
- Subfinder (optional, required only for `--subfinder`)

The toolkit was developed and tested on Windows. External tools must be available through the system `PATH`.

Check the installations with:

```bash
python --version
nmap --version
subfinder --version
```

## Installation

Clone the repository and enter the project directory:

```bash
git clone <repository-url>
cd Murayama.ReconToolKit
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows Git Bash:

```bash
source .venv/Scripts/activate
```

On Windows Command Prompt:

```cmd
.venv\Scripts\activate
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

On Linux/macOS:

```bash
source .venv/bin/activate
```

Install the project dependencies:

```bash
python -m pip install -r requirements.txt
```

Install the toolkit as an editable Python CLI:

```bash
python -m pip install -e .
```

After installation, the toolkit can be executed directly from the terminal:

```bash
murayama-recon --help
```

The editable installation is useful during development because changes to the source code are immediately reflected without reinstalling the package.

## Command-line interface

The project is packaged as a command-line tool. You do **not** need PyCharm or another IDE to run it after installation.

General syntax:

```bash
murayama-recon TARGET [OPTIONS]
```

Display all available options:

```bash
murayama-recon --help
```

The toolkit currently supports:

```text
--dns                 Perform DNS enumeration
--subdomains          Perform native subdomain enumeration
--subfinder           Perform passive discovery with Subfinder
--ports               Perform native TCP port scanning
--http                Perform HTTP reconnaissance
--wordlist PATH       Path to the subdomain wordlist
--threads NUMBER      Number of concurrent threads
--timeout SECONDS     Network timeout
--port PORT           Scan a single TCP port
--port-range RANGE    Scan a TCP port range
--nmap                Enrich discovered ports with Nmap
--output FILE         Save results as JSON
--verbose             Enable verbose/debug logging
```

Use `murayama-recon --help` as the authoritative reference for the version currently checked out.

## Startup banner

When the toolkit starts, it displays the custom **MurayamaRecon** terminal banner together with the toolkit version and authorized-use notice.

The banner is implemented separately from the reconnaissance logic so presentation remains isolated from the functional modules.

## Usage examples

### DNS enumeration

```bash
murayama-recon example.com --dns
```

### Native subdomain enumeration

```bash
murayama-recon example.com --subdomains
```

Use a custom wordlist and concurrency settings:

```bash
murayama-recon example.com \
  --subdomains \
  --wordlist wordlists/subdomains.txt \
  --threads 20 \
  --timeout 1
```

### Passive discovery with Subfinder

```bash
murayama-recon example.com \
  --subfinder \
  --threads 20 \
  --timeout 1
```

Subfinder results are first collected as passive candidates and then validated through DNS. This prevents historical or stale passive records from automatically being reported as confirmed assets.

A validation run against `example.com` during development demonstrated the difference clearly:

```text
[+] Passive Subdomain Discovery (Subfinder)
    Candidates discovered: 24948
    DNS validated: 1
    www.example.com -> ...
```

Passive-source results can change over time, so these counts are examples rather than expected fixed values.

### Consolidated subdomain discovery

Run the native and passive methods together:

```bash
murayama-recon example.com \
  --subdomains \
  --subfinder \
  --threads 20 \
  --timeout 1
```

The toolkit merges duplicate hosts and records which discovery mechanisms identified each one:

```text
[+] Consolidated Subdomain Results
    www.example.com -> ...
        Sources: native, subfinder
```

### Native TCP port scanning

Scan the default common-port set:

```bash
murayama-recon localhost --ports
```

Scan a single port:

```bash
murayama-recon localhost --ports --port 8080
```

Scan a range:

```bash
murayama-recon localhost --ports --port-range 1-1024
```

The target is not limited to `localhost`. The toolkit can operate against remote hosts and domains when testing is authorized.

### Nmap service enrichment

```bash
murayama-recon localhost --ports --nmap
```

The workflow is intentionally separated:

```text
Native scanner
      |
      v
Open ports
      |
      v
Nmap service enrichment
```

Example:

```text
[+] Port Scan
    8080/tcp open (http-alt)

[+] Nmap Service Enrichment
    8080/tcp http
        Microsoft Kestrel httpd
```

The native scanner remains responsible for discovery, while Nmap complements it with deeper service fingerprinting.

### HTTP reconnaissance

```bash
murayama-recon example.com --http
```

Combine port discovery and HTTP reconnaissance:

```bash
murayama-recon example.com --ports --http
```

The HTTP stage can collect information such as:

```text
URL
HTTP status
Server header
Content-Type
HTML title
Detected technologies
Security headers
```

Security headers currently checked include:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

A missing header is reported as an observation; its security impact depends on the application and deployment context.

### JSON output

```bash
murayama-recon example.com \
  --dns \
  --subdomains \
  --ports \
  --http \
  --output output/example.com.json
```

Reports contain metadata and results from the enabled stages, including consolidated subdomain data when applicable.

Example structure:

```json
{
  "tool": "Murayama Recon Automation Toolkit",
  "version": "0.1.0",
  "target": "example.com",
  "dns": {},
  "subdomains": [],
  "subfinder": [],
  "discovered_subdomains": [],
  "ports": [],
  "nmap": [],
  "http": []
}
```

### Verbose logging

```bash
murayama-recon example.com --ports --http --verbose
```

Verbose mode exposes additional diagnostic information useful during development and troubleshooting.

## Testing

Run the automated test suite with:

```bash
python -m pytest -v
```

The current test suite covers CLI port parsing, port-scanner behavior, HTTP title extraction, technology/security-header analysis, and JSON output.

## Design decisions

### Native scanner + Nmap

The project deliberately keeps its own concurrent TCP scanner instead of delegating discovery entirely to Nmap. This demonstrates socket programming and concurrency while allowing Nmap to perform the job at which it excels: deeper service fingerprinting.

### Native enumeration + Subfinder

Wordlist-based DNS enumeration and passive discovery provide different perspectives. Subfinder expands passive coverage, while the toolkit validates returned candidates through DNS before considering them confirmed.

### Correlation instead of duplicated output

When a host is identified by more than one mechanism, the toolkit consolidates it and preserves the discovery sources:

```json
{
  "subdomain": "www.example.com",
  "addresses": [
    "104.20.23.154",
    "172.66.147.243"
  ],
  "sources": [
    "native",
    "subfinder"
  ]
}
```

The actual address set may also contain IPv6 addresses.

### Installable CLI

The toolkit is packaged through `pyproject.toml` and exposes the `murayama-recon` command. This separates normal tool usage from the internal Python module layout and allows the project to behave like a conventional command-line security utility.

## Roadmap

Potential future improvements include:

- Additional passive reconnaissance sources
- Configurable port profiles
- Improved service fingerprinting
- TLS/certificate inspection
- HTTP redirect-chain analysis
- Additional technology fingerprints
- CSV/HTML reporting
- Expanded automated tests
- CI security and quality checks

## Ethical use

Reconnaissance can generate network traffic and expose information about systems. Use this project only on:

- systems you own;
- intentionally vulnerable labs;
- CTF environments where testing is permitted;
- environments for which you have explicit authorization.

The project is intended for cybersecurity education, portfolio development, and authorized security assessment workflows.

## Author

**Murayama**

Cybersecurity / AppSec portfolio project.
