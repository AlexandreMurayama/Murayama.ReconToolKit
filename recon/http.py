import re
import logging
import requests
from requests.exceptions import RequestException
from recon.technologies import (
    analyze_security_headers,
    analyze_technologies,
)

logger = logging.getLogger(__name__)

def _extract_title(html: str) -> str | None:
    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        html,
        re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return None

    return " ".join(match.group(1).split())


def analyze_http(
    target: str,
    port: int | None = None,
    timeout: float = 5.0,
) -> dict | None:
    urls = []

    if port is None:
        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

    elif port == 443:
        urls = [f"https://{target}"]

    elif port == 80:
        urls = [f"http://{target}"]

    elif port == 8443:
        urls = [f"https://{target}:{port}"]

    else:
        urls = [
            f"http://{target}:{port}",
            f"https://{target}:{port}",
        ]

    for url in urls:
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
            )

            return {
                "url": response.url,
                "status": response.status_code,
                "server": response.headers.get("Server", "unknown"),
                "content_type": response.headers.get(
                    "Content-Type",
                    "unknown",
                ),
                "title": _extract_title(response.text),
                "technologies": analyze_technologies(response.headers),
                "security_headers": analyze_security_headers(response.headers),
            }


        except RequestException as error:
            logger.debug(
                "HTTP request failed for %s: %s",
                url,
                error,
            )

            continue

    return None