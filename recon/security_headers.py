SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "recommendation": (
            "Enable HSTS on HTTPS responses to instruct "
            "browsers to use secure connections."
        ),
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "recommendation": (
            "Define a restrictive Content Security Policy "
            "appropriate for the application."
        ),
    },
    "X-Frame-Options": {
        "severity": "medium",
        "recommendation": (
            "Use DENY or SAMEORIGIN to reduce "
            "clickjacking exposure."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "recommendation": (
            "Set X-Content-Type-Options to nosniff."
        ),
    },
    "Referrer-Policy": {
        "severity": "low",
        "recommendation": (
            "Define an appropriate Referrer-Policy to "
            "control referrer information disclosure."
        ),
    },
    "Permissions-Policy": {
        "severity": "low",
        "recommendation": (
            "Define a Permissions-Policy restricting "
            "unnecessary browser features."
        ),
    },
}


def _find_header(
    headers,
    header_name: str,
) -> str | None:
    for name, value in headers.items():
        if name.lower() == header_name.lower():
            return value

    return None


def _analyze_x_frame_options(
    value: str,
) -> tuple[str, list[str]]:
    normalized = value.strip().upper()

    if normalized in {"DENY", "SAMEORIGIN"}:
        return "good", []

    return (
        "weak",
        [
            "Expected DENY or SAMEORIGIN.",
        ],
    )


def _analyze_x_content_type_options(
    value: str,
) -> tuple[str, list[str]]:
    if value.strip().lower() == "nosniff":
        return "good", []

    return (
        "weak",
        [
            "Expected value 'nosniff'.",
        ],
    )


def _analyze_hsts(
    value: str,
) -> tuple[str, list[str]]:
    normalized = value.lower()
    issues = []

    if "max-age=" not in normalized:
        issues.append(
            "Missing max-age directive."
        )

    if issues:
        return "weak", issues

    return "good", []


def _analyze_csp(
    value: str,
) -> tuple[str, list[str]]:
    normalized = value.lower()
    issues = []

    if "'unsafe-inline'" in normalized:
        issues.append(
            "unsafe-inline directive detected."
        )

    if "'unsafe-eval'" in normalized:
        issues.append(
            "unsafe-eval directive detected."
        )

    if "*" in normalized:
        issues.append(
            "Wildcard source detected."
        )

    if issues:
        return "weak", issues

    return "good", []


def _analyze_header_value(
    header: str,
    value: str,
) -> tuple[str, list[str]]:
    analyzers = {
        "Strict-Transport-Security":
            _analyze_hsts,
        "Content-Security-Policy":
            _analyze_csp,
        "X-Frame-Options":
            _analyze_x_frame_options,
        "X-Content-Type-Options":
            _analyze_x_content_type_options,
    }

    analyzer = analyzers.get(header)

    if analyzer is None:
        return "good", []

    return analyzer(value)


def analyze_security_headers(
    headers,
) -> dict:
    results = {}

    for header, metadata in SECURITY_HEADERS.items():
        value = _find_header(
            headers,
            header,
        )

        if value is None:
            results[header] = {
                "present": False,
                "value": None,
                "status": "missing",
                "severity": metadata["severity"],
                "issues": [
                    "Security header is missing."
                ],
                "recommendation":
                    metadata["recommendation"],
            }

            continue

        status, issues = _analyze_header_value(
            header,
            value,
        )

        results[header] = {
            "present": True,
            "value": value,
            "status": status,
            "severity": (
                metadata["severity"]
                if status == "weak"
                else None
            ),
            "issues": issues,
            "recommendation": (
                metadata["recommendation"]
                if status == "weak"
                else None
            ),
        }

    return results

def calculate_security_score(
    results: dict,
) -> dict:
    total_headers = len(results)

    if total_headers == 0:
        return {
            "score": 0,
            "good": 0,
            "weak": 0,
            "missing": 0,
        }

    good = 0
    weak = 0
    missing = 0

    points = 0

    for details in results.values():
        status = details["status"]

        if status == "good":
            good += 1
            points += 100

        elif status == "weak":
            weak += 1
            points += 50

        elif status == "missing":
            missing += 1

    score = round(
        points / total_headers
    )

    return {
        "score": score,
        "good": good,
        "weak": weak,
        "missing": missing,
    }