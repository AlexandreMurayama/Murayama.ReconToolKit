import argparse
from datetime import datetime, timezone

from recon.cli import get_ports_to_scan
from recon.dns import enumerate_dns
from recon.http import analyze_http
from recon.logger import configure_logging
from recon.nmap import run_nmap
from recon.output import save_json
from recon.ports import scan_ports
from recon.subdomains import enumerate_subdomains


def parse_args():
    parser = argparse.ArgumentParser(
        description="Murayama Recon Automation Toolkit"
    )

    parser.add_argument(
        "target",
        help="Target domain for authorized reconnaissance"
    )

    parser.add_argument(
        "--dns",
        action="store_true",
        help="Perform DNS enumeration"
    )

    parser.add_argument(
        "--subdomains",
        action="store_true",
        help="Perform subdomain enumeration"
    )

    parser.add_argument(
        "--ports",
        action="store_true",
        help="Perform port scanning"
    )

    parser.add_argument(
        "--http",
        action="store_true",
        help="Perform HTTP reconnaissance"
    )

    parser.add_argument(
        "--wordlist",
        default="wordlists/subdomains.txt",
        help="Path to subdomain wordlist"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Network timeout in seconds"
    )

    port_group = parser.add_mutually_exclusive_group()

    port_group.add_argument(
        "--port",
        type=int,
        help="Scan a single TCP port"
    )

    port_group.add_argument(
        "--port-range",
        help="TCP port range to scan (example: 1-1024)"
    )

    parser.add_argument(
        "--nmap",
        action="store_true",
        help="Enrich discovered ports with Nmap service detection"
    )

    parser.add_argument(
        "--output",
        help="Save reconnaissance results to a JSON file"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    return parser.parse_args()


def print_http_result(result: dict):
    print(f"\n    URL:          {result['url']}")
    print(f"    Status:       {result['status']}")
    print(f"    Server:       {result['server']}")
    print(f"    Content-Type: {result['content_type']}")
    print(
        f"    Title:        "
        f"{result['title'] or 'unknown'}"
    )

    print("\n    Technologies:")

    technologies = result["technologies"]

    if technologies:
        for name, value in technologies.items():
            print(f"        {name}: {value}")
    else:
        print("        No technologies identified")

    print("\n    Security Headers:")

    for header, details in result["security_headers"].items():
        if details["present"]:
            print(
                f"        [present] {header}: "
                f"{details['value']}"
            )
        else:
            print(
                f"        [missing] {header}"
            )


def print_nmap_result(result: dict):
    print(
        f"    {result['port']}/{result['protocol']} "
        f"{result['service']}"
    )

    product = result.get("product")
    version = result.get("version")

    details_parts = []

    if product:
        details_parts.append(product)

    if version:
        details_parts.append(version)

    details = " ".join(details_parts)

    if details:
        print(f"        {details}")


def main():
    args = parse_args()

    configure_logging(args.verbose)

    if args.threads < 1:
        raise SystemExit(
            "[-] --threads must be greater than 0"
        )

    if args.timeout <= 0:
        raise SystemExit(
            "[-] --timeout must be greater than 0"
        )

    if args.nmap and not args.ports:
        raise SystemExit(
            "[-] --nmap requires --ports"
        )

    recon_results = {
        "tool": "Murayama Recon Automation Toolkit",
        "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": args.target,
        "dns": {},
        "subdomains": [],
        "ports": [],
        "nmap": [],
        "http": [],
    }

    print("[*] Murayama Recon Automation Toolkit")
    print(f"[*] Target: {args.target}")

    # DNS Enumeration
    if args.dns:
        print("\n[+] DNS Enumeration")

        try:
            dns_results = enumerate_dns(args.target)

            recon_results["dns"] = dns_results

            for record_type, records in dns_results.items():
                print(f"\n    {record_type}:")

                if records:
                    for record in records:
                        print(f"        {record}")
                else:
                    print("        No records found")

        except ValueError as error:
            print(f"[-] {error}")

    # Subdomain Enumeration
    if args.subdomains:
        print("\n[+] Subdomain Enumeration")

        try:
            subdomains, wildcard_addresses = enumerate_subdomains(
                target=args.target,
                wordlist_path=args.wordlist,
                threads=args.threads,
                timeout=args.timeout,
            )

            recon_results["subdomains"] = subdomains

            if wildcard_addresses:
                print(
                    "[!] Wildcard DNS detected: "
                    + ", ".join(wildcard_addresses)
                )

            if subdomains:
                for result in subdomains:
                    addresses = ", ".join(
                        result["addresses"]
                    )

                    print(
                        f"    {result['subdomain']} "
                        f"-> {addresses}"
                    )
            else:
                print("    No subdomains found")

        except FileNotFoundError as error:
            print(f"[-] {error}")

    port_results = []

    # Native TCP Port Scan
    if args.ports:
        print("\n[+] Port Scan")

        try:
            ports_to_scan = get_ports_to_scan(args)

            port_results = scan_ports(
                target=args.target,
                ports=ports_to_scan,
                threads=args.threads,
                timeout=args.timeout,
            )

            recon_results["ports"] = port_results

            if port_results:
                for result in port_results:
                    print(
                        f"    {result['port']}/tcp "
                        f"open ({result['service']})"
                    )
            else:
                print("    No open ports found")

            # Nmap enrichment
            if args.nmap and port_results:
                print("\n[+] Nmap Service Enrichment")

                discovered_ports = [
                    result["port"]
                    for result in port_results
                ]

                nmap_results = run_nmap(
                    target=args.target,
                    ports=discovered_ports,
                    timeout=30.0,
                )

                recon_results["nmap"] = nmap_results

                if nmap_results:
                    for result in nmap_results:
                        print_nmap_result(result)
                else:
                    print(
                        "    No additional service "
                        "information detected"
                    )

            elif args.nmap:
                print(
                    "\n[+] Nmap Service Enrichment"
                )
                print(
                    "    No open ports available "
                    "for Nmap enrichment"
                )

        except ValueError as error:
            print(f"[-] {error}")

    # HTTP Reconnaissance
    if args.http:
        print("\n[+] HTTP Reconnaissance")

        web_ports = []

        if port_results:
            web_ports = [
                result["port"]
                for result in port_results
                if result["port"]
                in {80, 443, 8080, 8443}
            ]

        if web_ports:
            http_results = []

            for port in web_ports:
                result = analyze_http(
                    target=args.target,
                    port=port,
                    timeout=args.timeout,
                )

                if result:
                    http_results.append(result)
                    recon_results["http"].append(result)
                else:
                    print(
                        f"    Port {port}: "
                        f"no valid HTTP/HTTPS response"
                    )

            if http_results:
                for result in http_results:
                    print_http_result(result)
            else:
                print(
                    "    No HTTP/HTTPS service detected"
                )

        else:
            result = analyze_http(
                target=args.target,
                timeout=args.timeout,
            )

            if result:
                recon_results["http"].append(result)
                print_http_result(result)
            else:
                print(
                    "    No HTTP/HTTPS service detected"
                )

    # JSON Output
    if args.output:
        try:
            save_json(
                recon_results,
                args.output,
            )

            print(
                f"\n[+] Results saved to: "
                f"{args.output}"
            )

        except ValueError as error:
            print(f"\n[-] {error}")


if __name__ == "__main__":
    main()