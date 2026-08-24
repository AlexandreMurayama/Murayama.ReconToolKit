from recon.security_headers import analyze_security_headers


def analyze_technologies(headers) -> dict:
    technologies = {}

    server = headers.get("Server")
    powered_by = headers.get("X-Powered-By")

    if server:
        technologies["server"] = server

    if powered_by:
        technologies["powered_by"] = powered_by

    return technologies