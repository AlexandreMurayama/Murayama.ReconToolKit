# Murayama Recon Automation Toolkit

[English](README.md) \| [Português (Brasil)](README-PT-BR.md)

A modular Python reconnaissance toolkit built for authorized
cybersecurity assessments, security labs, and educational use.

The project combines **native reconnaissance components implemented in
Python** with optional integrations for established security tools. Its
goal is not to replace tools such as Nmap or Subfinder, but to
demonstrate how reconnaissance stages can be automated, validated,
correlated, and exported through a single workflow.

> **Authorized use only.** Run this toolkit only against systems you own
> or systems for which you have explicit permission to perform security
> testing.

## Features

### Native components

-   DNS enumeration (`A`, `AAAA`, `MX`, `NS`, `TXT`)
-   Concurrent subdomain enumeration using wordlists
-   Wildcard DNS detection
-   IPv4 and IPv6 subdomain resolution
-   Concurrent TCP port scanning
-   Native concurrent service banner grabbing
-   Active HTTP and HTTPS/TLS banner probes
-   Passive banner collection for services that identify themselves on
    connection
-   SMTP probing support
-   Common service identification
-   HTTP/HTTPS reconnaissance
-   HTML title extraction
-   Basic technology fingerprinting
-   Security Header Analyzer with value validation
-   Header classification (`GOOD`, `WEAK`, `MISSING`)
-   Finding severity, issues, and remediation recommendations
-   Security Score (`0-100`)
-   Subdomain result correlation and deduplication
-   JSON report generation
-   Verbose/debug logging
-   Automated tests with pytest (32 tests currently passing)
-   Installable command-line interface (`murayama-recon`)
-   Custom MurayamaRecon terminal banner

### External enrichment

-   **Nmap** --- enriches ports discovered by the native scanner with
    service/product/version information
-   **Subfinder** --- adds passive subdomain discovery, followed by DNS
    validation performed by the toolkit

The native scanner remains responsible for initial port discovery. Nmap
is an optional enrichment stage. Likewise, passive Subfinder results are
treated as **candidates**, not confirmed assets, until they successfully
resolve through DNS.

## Architecture

``` text
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

``` text
Murayama.ReconToolKit/
├── recon/
│   ├── __init__.py
│   ├── app.py
│   ├── banner.py
│   ├── banner_grabber.py
│   ├── cli.py
│   ├── cli_entry.py
│   ├── dns.py
│   ├── http.py
│   ├── logger.py
│   ├── nmap.py
│   ├── output.py
│   ├── security_headers.py
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

-   Python 3
-   pip
-   Nmap (optional, required only for `--nmap`)
-   Subfinder (optional, required only for `--subfinder`)

The toolkit was developed and tested on Windows. External tools must be
available through the system `PATH`.

Check the installations with:

``` bash
python --version
nmap --version
subfinder --version
```

## Installation

Clone the repository and enter the project directory:

``` bash
git clone <repository-url>
cd Murayama.ReconToolKit
```

Create a virtual environment:

``` bash
python -m venv .venv
```

Activate it on Windows Git Bash:

``` bash
source .venv/Scripts/activate
```

On Windows Command Prompt:

``` cmd
.venv\Scripts\activate
```

On Windows PowerShell:

``` powershell
.venv\Scripts\Activate.ps1
```

On Linux/macOS:

``` bash
source .venv/bin/activate
```

Install the project dependencies:

``` bash
python -m pip install -r requirements.txt
```

Install the toolkit as an editable Python CLI:

``` bash
python -m pip install -e .
```

After installation, the toolkit can be executed directly from the
terminal:

``` bash
murayama-recon --help
```

The editable installation is useful during development because changes
to the source code are immediately reflected without reinstalling the
package.

## Command-line interface

The project is packaged as a command-line tool. You do **not** need
PyCharm or another IDE to run it after installation.

General syntax:

``` bash
murayama-recon TARGET [OPTIONS]
```

Display all available options:

``` bash
murayama-recon --help
```

The toolkit currently supports:

``` text
--dns                 Perform DNS enumeration
--subdomains          Perform native subdomain enumeration
--subfinder           Perform passive discovery with Subfinder
--ports               Perform native TCP port scanning
--banners             Grab service banners from discovered open ports
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

Use `murayama-recon --help` as the authoritative reference for the
version currently checked out.

## Startup banner

When the toolkit starts, it displays the custom **MurayamaRecon**
terminal banner together with the toolkit version and authorized-use
notice.

The banner is implemented separately from the reconnaissance logic so
presentation remains isolated from the functional modules.

## Usage examples

### DNS enumeration

``` bash
murayama-recon example.com --dns
```

### Native subdomain enumeration

``` bash
murayama-recon example.com --subdomains
```

Use a custom wordlist and concurrency settings:

``` bash
murayama-recon example.com \
  --subdomains \
  --wordlist wordlists/subdomains.txt \
  --threads 20 \
  --timeout 1
```

### Passive discovery with Subfinder

``` bash
murayama-recon example.com \
  --subfinder \
  --threads 20 \
  --timeout 1
```

Subfinder results are first collected as passive candidates and then
validated through DNS. This prevents historical or stale passive records
from automatically being reported as confirmed assets.

A validation run against `example.com` during development demonstrated
the difference clearly:

``` text
[+] Passive Subdomain Discovery (Subfinder)
    Candidates discovered: 24948
    DNS validated: 1
    www.example.com -> ...
```

Passive-source results can change over time, so these counts are
examples rather than expected fixed values.

### Consolidated subdomain discovery

Run the native and passive methods together:

``` bash
murayama-recon example.com \
  --subdomains \
  --subfinder \
  --threads 20 \
  --timeout 1
```

The toolkit merges duplicate hosts and records which discovery
mechanisms identified each one:

``` text
[+] Consolidated Subdomain Results
    www.example.com -> ...
        Sources: native, subfinder
```

### Native TCP port scanning

Scan the default common-port set:

``` bash
murayama-recon localhost --ports
```

Scan a single port:

``` bash
murayama-recon localhost --ports --port 8080
```

Scan a range:

``` bash
murayama-recon localhost --ports --port-range 1-1024
```

The target is not limited to `localhost`. The toolkit can operate
against remote hosts and domains when testing is authorized.

### Native banner grabbing

Banner grabbing is performed after the native port scanner discovers
open TCP ports:

``` bash
murayama-recon localhost --ports --banners
```

The banner module uses concurrent workers and combines passive and
active techniques. Services such as SSH and FTP may identify themselves
immediately after connection, while HTTP services are actively probed.
HTTPS on the conventional TLS ports uses a TLS handshake before the HTTP
probe, and SMTP ports support protocol-aware probing.

Example:

``` text
[+] Port Scan
    8080/tcp open (http-alt)

[+] Banner Grabbing
    8080/tcp
        HTTP/1.1 404 Not Found
        Connection: close
        Server: Kestrel
```

A `404 Not Found` response is still useful reconnaissance evidence: it
confirms that an HTTP service answered the request and may expose
identifying headers such as `Server`.

Banner grabbing and Nmap enrichment are complementary. The native module
demonstrates direct socket/protocol interaction, while Nmap provides
deeper service fingerprinting.

### Nmap service enrichment

``` bash
murayama-recon localhost --ports --nmap
```

The workflow is intentionally separated:

``` text
Native scanner
      |
      v
Open ports
      |
      v
Nmap service enrichment
```

Example:

``` text
[+] Port Scan
    8080/tcp open (http-alt)

[+] Nmap Service Enrichment
    8080/tcp http
        Microsoft Kestrel httpd
```

The native scanner remains responsible for discovery, while Nmap
complements it with deeper service fingerprinting.

### HTTP reconnaissance

``` bash
murayama-recon example.com --http
```

Combine port discovery and HTTP reconnaissance:

``` bash
murayama-recon example.com --ports --http
```

The HTTP stage can collect information such as:

``` text
URL
HTTP status
Server header
Content-Type
HTML title
Detected technologies
Security headers
```

### Security Header Analyzer

The HTTP reconnaissance stage includes a native Security Header
Analyzer. It checks both the presence of selected headers and, where
supported, whether their values follow basic defensive expectations.

Headers currently analyzed include:

-   `Strict-Transport-Security`
-   `Content-Security-Policy`
-   `X-Frame-Options`
-   `X-Content-Type-Options`
-   `Referrer-Policy`
-   `Permissions-Policy`

Each header is classified as:

-   `GOOD` --- present and accepted by the current validation rules
-   `WEAK` --- present, but with a potentially weak or unexpected value
-   `MISSING` --- not present in the analyzed response

Current value-aware checks include HSTS `max-age`, `X-Frame-Options`
(`DENY` or `SAMEORIGIN`), `X-Content-Type-Options` (`nosniff`), and CSP
detection of `'unsafe-inline'`, `'unsafe-eval'`, and wildcard sources.

Weak or missing headers include severity metadata, identified issues,
and a remediation recommendation. The toolkit also calculates a simple
Security Score from `0` to `100`:

``` text
GOOD    = 100% credit
WEAK    =  50% credit
MISSING =   0% credit
```

Example:

``` text
[+] HTTP Reconnaissance

    Security Header Analysis:

        [WEAK] Content-Security-Policy
            Value: default-src * 'unsafe-inline'
            Severity: medium
            Issues:
                - unsafe-inline directive detected.
                - Wildcard source detected.

        [GOOD] X-Frame-Options
            Value: SAMEORIGIN

    Security Score:
        Score:   25/100
        Good:    1
        Weak:    1
        Missing: 4
```

The score is a reconnaissance aid, not a vulnerability rating or a
substitute for manual security review. Header relevance and impact
depend on the application, browser behavior, deployment architecture,
and other controls.

### JSON output

``` bash
murayama-recon example.com \
  --dns \
  --subdomains \
  --ports \
  --http \
  --output output/example.com.json
```

Reports contain metadata and results from the enabled stages, including
consolidated subdomain data when applicable.

Example structure:

``` json
{
  "tool": "Murayama Recon Automation Toolkit",
  "version": "0.1.0",
  "target": "example.com",
  "dns": {},
  "subdomains": [],
  "subfinder": [],
  "discovered_subdomains": [],
  "ports": [],
  "banners": [],
  "nmap": [],
  "http": []
}
```

### Verbose logging

``` bash
murayama-recon example.com --ports --http --verbose
```

Verbose mode exposes additional diagnostic information useful during
development and troubleshooting.

## Testing

Run the automated test suite with:

``` bash
python -m pytest -v
```

The current test suite covers CLI port parsing, port-scanner behavior,
HTTP title extraction, technology/security-header analysis, and JSON
output.

## Design decisions

### Native scanner + banner grabber + Nmap

The toolkit separates three reconnaissance layers:

``` text
Native TCP scanner
        |
        v
    Open ports
     /      \
    v        v
Native      Nmap
banner      enrichment
grabber
```

The native banner grabber interacts directly with discovered services
using sockets and protocol-aware probes. Nmap remains optional and
provides more advanced service/product fingerprinting. This makes the
two mechanisms complementary rather than redundant.

The project deliberately keeps its own concurrent TCP scanner instead of
delegating discovery entirely to Nmap. This demonstrates socket
programming and concurrency while allowing Nmap to perform the job at
which it excels: deeper service fingerprinting.

### Native enumeration + Subfinder

Wordlist-based DNS enumeration and passive discovery provide different
perspectives. Subfinder expands passive coverage, while the toolkit
validates returned candidates through DNS before considering them
confirmed.

### Correlation instead of duplicated output

When a host is identified by more than one mechanism, the toolkit
consolidates it and preserves the discovery sources:

``` json
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

The toolkit is packaged through `pyproject.toml` and exposes the
`murayama-recon` command. This separates normal tool usage from the
internal Python module layout and allows the project to behave like a
conventional command-line security utility.

## Roadmap

Potential future improvements include:

-   Additional passive reconnaissance sources
-   Configurable port profiles
-   Additional protocol-aware banner probes
-   Improved service fingerprinting
-   TLS/certificate inspection
-   HTTP redirect-chain analysis
-   Additional technology fingerprints
-   CSV/HTML reporting
-   Expanded automated tests
-   CI security and quality checks

## Ethical use

Reconnaissance can generate network traffic and expose information about
systems. Use this project only on:

-   systems you own;
-   intentionally vulnerable labs;
-   CTF environments where testing is permitted;
-   environments for which you have explicit authorization.

The project is intended for cybersecurity education, portfolio
development, and authorized security assessment workflows.

## Author

**Murayama**

Cybersecurity / AppSec portfolio project.
