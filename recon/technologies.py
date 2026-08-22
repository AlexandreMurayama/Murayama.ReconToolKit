SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Referrer-Policy": "Referrer policy",
    "Permissions-Policy": "Browser permissions policy",
}


def analyze_technologies(headers) -> dict:
    technologies = {}

    server = headers.get("Server")
    powered_by = headers.get("X-Powered-By")

    if server:
        technologies["server"] = server

    if powered_by:
        technologies["powered_by"] = powered_by

    return technologies


def analyze_security_headers(headers) -> dict:
    results = {}

    for header, description in SECURITY_HEADERS.items():
        value = headers.get(header)

        results[header] = {
            "description": description,
            "present": value is not None,
            "value": value,
        }

    return results