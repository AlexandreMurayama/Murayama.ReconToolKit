import argparse
from recon.dns import enumerate_dns
from recon.subdomains import enumerate_subdomains
from recon.ports import scan_ports
from recon.http import analyze_http

COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    8080,
    8443,
]

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
        help="DNS query timeout in seconds"
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

    return parser.parse_args()


def get_ports_to_scan(args) -> list[int]:
    if args.port is not None:
        if not 1 <= args.port <= 65535:
            raise ValueError(
                "Port must be between 1 and 65535"
            )

        return [args.port]

    if args.port_range:
        try:
            start_text, end_text = args.port_range.split("-", maxsplit=1)

            start = int(start_text)
            end = int(end_text)

        except ValueError as error:
            raise ValueError(
                "Port range must use the format START-END"
            ) from error

        if not 1 <= start <= 65535:
            raise ValueError(
                "Start port must be between 1 and 65535"
            )

        if not 1 <= end <= 65535:
            raise ValueError(
                "End port must be between 1 and 65535"
            )

        if start > end:
            raise ValueError(
                "Start port cannot be greater than end port"
            )

        return list(range(start, end + 1))

    return COMMON_PORTS

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

def main():
    args = parse_args()

    if args.threads < 1:
        raise SystemExit("[-] --threads must be greater than 0")

    if args.timeout <= 0:
        raise SystemExit("[-] --timeout must be greater than 0")

    print("[*] Murayama Recon Automation Toolkit")
    print(f"[*] Target: {args.target}")

    if args.dns:
        print("\n[+] DNS Enumeration")

        try:
            dns_results = enumerate_dns(args.target)

            for record_type, records in dns_results.items():
                print(f"\n    {record_type}:")

                if records:
                    for record in records:
                        print(f"        {record}")
                else:
                    print("        No records found")

        except ValueError as error:
            print(f"[-] {error}")

    if args.subdomains:
        print("\n[+] Subdomain Enumeration")

        try:
            subdomains, wildcard_addresses = enumerate_subdomains(
                target=args.target,
                wordlist_path=args.wordlist,
                threads=args.threads,
                timeout=args.timeout,
            )

            if wildcard_addresses:
                print(
                    "[!] Wildcard DNS detected: "
                    + ", ".join(wildcard_addresses)
                )

            if subdomains:
                for result in subdomains:
                    addresses = ", ".join(result["addresses"])

                    print(
                        f"    {result['subdomain']} -> {addresses}"
                    )
            else:
                print("    No subdomains found")

        except FileNotFoundError as error:
            print(f"[-] {error}")

    port_results = []

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

            if port_results:
                for result in port_results:
                    print(
                        f"    {result['port']}/tcp "
                        f"open ({result['service']})"
                    )
            else:
                print("    No open ports found")

        except ValueError as error:
            print(f"[-] {error}")

    if args.http:
        print("\n[+] HTTP Reconnaissance")

        web_ports = []

        if port_results:
            web_ports = [
                result["port"]
                for result in port_results
                if result["port"] in {80, 443, 8080, 8443}
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
                else:
                    print(
                        f"    Port {port}: "
                        f"no valid HTTP/HTTPS response"
                    )

            if http_results:
                for result in http_results:
                    print_http_result(result)
            else:
                print("    No HTTP/HTTPS service detected")

        else:
            result = analyze_http(
                target=args.target,
                timeout=args.timeout,
            )

            if result:
                print_http_result(result)
            else:
                print("    No HTTP/HTTPS service detected")


if __name__ == "__main__":
    main()