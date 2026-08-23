import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver


def _resolve_subdomain(
    hostname: str,
    timeout: float,
) -> dict | None:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    addresses = set()

    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(
                hostname,
                record_type,
            )

            for answer in answers:
                addresses.add(answer.to_text())

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.Timeout,
            dns.resolver.NoNameservers,
        ):
            continue

    if not addresses:
        return None

    return {
        "subdomain": hostname,
        "addresses": sorted(addresses),
    }


def _validate_candidates(
    candidates: set[str],
    threads: int,
    timeout: float,
) -> list[dict]:
    validated = []

    with ThreadPoolExecutor(
        max_workers=threads
    ) as executor:
        futures = [
            executor.submit(
                _resolve_subdomain,
                hostname,
                timeout,
            )
            for hostname in candidates
        ]

        for future in as_completed(futures):
            result = future.result()

            if result is not None:
                validated.append(result)

    validated.sort(
        key=lambda item: item["subdomain"]
    )

    return validated


def run_subfinder(
    target: str,
    threads: int = 10,
    timeout: float = 120.0,
    dns_timeout: float = 2.0,
) -> tuple[list[dict], int]:
    command = [
        "subfinder",
        "-d",
        target,
        "-silent",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    except subprocess.TimeoutExpired as error:
        raise ValueError(
            f"Subfinder timed out after {timeout} seconds"
        ) from error

    except FileNotFoundError as error:
        raise ValueError(
            "Subfinder executable was not found in PATH"
        ) from error

    if result.returncode != 0:
        raise ValueError(
            f"Subfinder failed: {result.stderr.strip()}"
        )

    candidates = {
        line.strip().lower()
        for line in result.stdout.splitlines()
        if line.strip()
    }

    validated = _validate_candidates(
        candidates=candidates,
        threads=threads,
        timeout=dns_timeout,
    )

    return validated, len(candidates)