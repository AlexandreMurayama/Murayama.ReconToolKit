import argparse
from recon.dns import enumerate_dns


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

    return parser.parse_args()


def main():
    args = parse_args()

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
        print("[+] Subdomain enumeration enabled")

    if args.ports:
        print("[+] Port scanning enabled")

    if args.http:
        print("[+] HTTP reconnaissance enabled")


if __name__ == "__main__":
    main()