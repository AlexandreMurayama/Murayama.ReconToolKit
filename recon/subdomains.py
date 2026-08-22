from pathlib import Path
import secrets
import string

import dns.resolver


def _generate_random_subdomain(length: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits

    return "".join(
        secrets.choice(alphabet)
        for _ in range(length)
    )


def _resolve_ipv4(hostname: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(hostname, "A")

        return sorted(
            answer.to_text()
            for answer in answers
        )

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.Timeout,
        dns.resolver.NoNameservers,
    ):
        return []


def detect_wildcard_dns(target: str) -> list[str]:
    random_prefix = _generate_random_subdomain()
    random_hostname = f"{random_prefix}.{target}"

    return _resolve_ipv4(random_hostname)


def enumerate_subdomains(target: str, wordlist_path: str):
    wordlist = Path(wordlist_path)

    if not wordlist.exists():
        raise FileNotFoundError(
            f"Wordlist not found: {wordlist_path}"
        )

    wildcard_addresses = detect_wildcard_dns(target)

    results = []

    with wordlist.open("r", encoding="utf-8") as file:
        for line in file:
            prefix = line.strip()

            if not prefix or prefix.startswith("#"):
                continue

            subdomain = f"{prefix}.{target}"
            addresses = _resolve_ipv4(subdomain)

            if not addresses:
                continue

            if wildcard_addresses and addresses == wildcard_addresses:
                continue

            results.append(
                {
                    "subdomain": subdomain,
                    "addresses": addresses,
                }
            )

    return results, wildcard_addresses