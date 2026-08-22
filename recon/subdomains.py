from concurrent.futures import ThreadPoolExecutor, as_completed
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


def _resolve_ipv4(hostname: str, timeout: float) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        answers = resolver.resolve(hostname, "A")

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


def detect_wildcard_dns(target: str, timeout: float) -> list[str]:
    random_prefix = _generate_random_subdomain()
    random_hostname = f"{random_prefix}.{target}"

    return _resolve_ipv4(random_hostname, timeout)


def _check_subdomain(
    prefix: str,
    target: str,
    timeout: float,
) -> dict | None:
    subdomain = f"{prefix}.{target}"
    addresses = _resolve_ipv4(subdomain, timeout)

    if not addresses:
        return None

    return {
        "subdomain": subdomain,
        "addresses": addresses,
    }


def enumerate_subdomains(
    target: str,
    wordlist_path: str,
    threads: int = 10,
    timeout: float = 2.0,
):
    wordlist = Path(wordlist_path)

    if not wordlist.exists():
        raise FileNotFoundError(
            f"Wordlist not found: {wordlist_path}"
        )

    wildcard_addresses = detect_wildcard_dns(
        target,
        timeout,
    )

    prefixes = []

    with wordlist.open("r", encoding="utf-8") as file:
        for line in file:
            prefix = line.strip()

            if not prefix or prefix.startswith("#"):
                continue

            prefixes.append(prefix)

    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(
                _check_subdomain,
                prefix,
                target,
                timeout,
            ): prefix
            for prefix in prefixes
        }

        for future in as_completed(futures):
            result = future.result()

            if result is None:
                continue

            if (
                wildcard_addresses
                and result["addresses"] == wildcard_addresses
            ):
                continue

            results.append(result)

    results.sort(
        key=lambda item: item["subdomain"]
    )

    return results, wildcard_addresses