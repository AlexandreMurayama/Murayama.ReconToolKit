import argparse
from recon.dns import enumerate_dns
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
        help="DNS query timeout in seconds"
    )

    return parser.parse_args()


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

    if args.ports:
        print("[+] Port scanning enabled")

    if args.http:
        print("[+] HTTP reconnaissance enabled")


if __name__ == "__main__":
    main()