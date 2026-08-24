import socket
import ssl
import tempfile
from pathlib import Path
from datetime import datetime, timezone


def _parse_certificate_date(
    value: str,
) -> datetime:
    timestamp = ssl.cert_time_to_seconds(value)

    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    )


def _calculate_days_remaining(
    not_after: datetime,
) -> int:
    now = datetime.now(timezone.utc)

    return (not_after - now).days


def _analyze_protocol(
    protocol: str | None,
) -> dict:
    if protocol == "TLSv1.3":
        return {
            "status": "good",
            "severity": None,
            "issues": [],
            "recommendation": None,
        }

    if protocol == "TLSv1.2":
        return {
            "status": "good",
            "severity": None,
            "issues": [],
            "recommendation": None,
        }

    if protocol in (
        "TLSv1",
        "TLSv1.1",
        "SSLv2",
        "SSLv3",
    ):
        return {
            "status": "weak",
            "severity": "high",
            "issues": [
                f"Deprecated TLS/SSL protocol negotiated: {protocol}."
            ],
            "recommendation":
                "Disable legacy SSL/TLS protocols and require TLS 1.2 or TLS 1.3.",
        }

    return {
        "status": "unknown",
        "severity": "info",
        "issues": [
            f"Unable to classify protocol: {protocol}."
        ],
        "recommendation":
            "Review the negotiated TLS protocol manually.",
    }


def _analyze_cipher(
    cipher: tuple,
) -> dict:
    name = cipher[0]
    bits = cipher[2]

    weak_keywords = (
        "RC4",
        "DES",
        "3DES",
        "NULL",
        "EXPORT",
    )

    issues = []

    if any(
        keyword in name.upper()
        for keyword in weak_keywords
    ):
        issues.append(
            f"Potentially weak cipher detected: {name}."
        )

    if bits < 128:
        issues.append(
            f"Cipher strength is only {bits} bits."
        )

    if issues:
        return {
            "status": "weak",
            "severity": "high",
            "issues": issues,
            "recommendation":
                "Disable weak cipher suites and prefer modern AEAD ciphers.",
        }

    return {
        "status": "good",
        "severity": None,
        "issues": [],
        "recommendation": None,
    }


def _analyze_certificate(
    days_remaining: int,
) -> dict:
    if days_remaining < 0:
        return {
            "status": "high",
            "severity": "high",
            "issues": [
                f"Certificate expired {abs(days_remaining)} days ago."
            ],
            "recommendation":
                "Renew and deploy a valid TLS certificate immediately.",
        }

    if days_remaining <= 7:
        return {
            "status": "weak",
            "severity": "high",
            "issues": [
                f"Certificate expires in {days_remaining} days."
            ],
            "recommendation":
                "Renew the TLS certificate as soon as possible.",
        }

    if days_remaining <= 30:
        return {
            "status": "weak",
            "severity": "medium",
            "issues": [
                f"Certificate expires in {days_remaining} days."
            ],
            "recommendation":
                "Plan certificate renewal before expiration.",
        }

    return {
        "status": "good",
        "severity": None,
        "issues": [],
        "recommendation": None,
    }


def _hostname_matches(
    hostname: str,
    pattern: str,
) -> bool:
    hostname = hostname.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")

    if pattern.startswith("*."):
        suffix = pattern[2:]

        hostname_parts = hostname.split(".")
        suffix_parts = suffix.split(".")

        return (
            len(hostname_parts) == len(suffix_parts) + 1
            and hostname_parts[1:] == suffix_parts
        )

    return hostname == pattern


def _hostname_matches(
    hostname: str,
    pattern: str,
) -> bool:
    hostname = hostname.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")

    if pattern.startswith("*."):
        suffix = pattern[2:]

        hostname_parts = hostname.split(".")
        suffix_parts = suffix.split(".")

        return (
            len(hostname_parts) == len(suffix_parts) + 1
            and hostname_parts[1:] == suffix_parts
        )

    return hostname == pattern


def _analyze_hostname(
    target: str,
    common_name: str | None,
    sans: list[str],
) -> dict:
    names = sans if sans else []

    # CN fallback is used only when no DNS SAN exists.
    if not names and common_name:
        names = [common_name]

    for name in names:
        if _hostname_matches(
            target,
            name,
        ):
            return {
                "status": "good",
                "severity": None,
                "issues": [],
                "recommendation": None,
            }

    return {
        "status": "high",
        "severity": "high",
        "issues": [
            (
                f"Certificate does not match "
                f"target hostname: {target}."
            )
        ],
        "recommendation": (
            "Deploy a certificate whose DNS SAN "
            "matches the target hostname."
        ),
    }


def calculate_tls_security_score(
    security_analysis: dict,
) -> dict:
    total = len(security_analysis)

    if total == 0:
        return {
            "score": 0,
            "good": 0,
            "weak": 0,
            "high": 0,
            "unknown": 0,
        }

    points = 0
    good = 0
    weak = 0
    high = 0
    unknown = 0

    for details in security_analysis.values():
        status = details["status"]

        if status == "good":
            good += 1
            points += 100

        elif status == "weak":
            weak += 1
            points += 50

        elif status == "high":
            high += 1

        else:
            unknown += 1
            points += 25

    score = round(
        points / total
    )

    return {
        "score": score,
        "good": good,
        "weak": weak,
        "high": high,
        "unknown": unknown,
    }


def _analyze_certificate_trust(
    trusted: bool,
    verification_error: str | None = None,
) -> dict:
    if trusted:
        return {
            "status": "good",
            "severity": None,
            "issues": [],
            "recommendation": None,
        }

    issue = "Certificate trust validation failed."

    if verification_error:
        issue = (
            f"Certificate trust validation failed: "
            f"{verification_error}"
        )

    return {
        "status": "high",
        "severity": "high",
        "issues": [
            issue
        ],
        "recommendation": (
            "Deploy a certificate issued by a trusted "
            "certificate authority and ensure the complete "
            "certificate chain is correctly configured."
        ),
    }


def _verify_certificate_trust(
    target: str,
    port: int,
    timeout: float,
) -> tuple[bool, str | None]:
    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (target, port),
            timeout=timeout,
        ) as tcp_socket:

            with context.wrap_socket(
                tcp_socket,
                server_hostname=target,
            ):
                return True, None

    except ssl.SSLCertVerificationError as error:
        return False, str(error)

    except (
        socket.timeout,
        socket.gaierror,
        ConnectionRefusedError,
        ssl.SSLError,
        OSError,
    ) as error:
        raise ValueError(
            f"TLS connection failed: {error}"
        ) from error


def _decode_der_certificate(
    der_certificate: bytes,
) -> dict:
    pem_certificate = ssl.DER_cert_to_PEM_cert(
        der_certificate
    )

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".pem",
        delete=False,
        encoding="utf-8",
    ) as temp_file:
        temp_file.write(
            pem_certificate
        )

        temp_path = Path(
            temp_file.name
        )

    try:
        return ssl._ssl._test_decode_cert(
            str(temp_path)
        )

    finally:
        temp_path.unlink(
            missing_ok=True
        )


def analyze_tls(
    target: str,
    port: int = 443,
    timeout: float = 5.0,
) -> dict:

    trusted, verification_error = (
        _verify_certificate_trust(
            target=target,
            port=port,
            timeout=timeout,
        )
    )

    if trusted:
        context = ssl.create_default_context()

    else:
        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_CLIENT
        )

        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection(
            (target, port),
            timeout=timeout,
        ) as tcp_socket:

            with context.wrap_socket(
                tcp_socket,
                server_hostname=target,
            ) as tls_socket:

                if trusted:
                    certificate = tls_socket.getpeercert()

                else:
                    der_certificate = tls_socket.getpeercert(
                        binary_form=True
                    )

                    if not der_certificate:
                        raise ValueError(
                            "Unable to retrieve peer certificate"
                        )

                    certificate = _decode_der_certificate(
                        der_certificate
                    )

                cipher = tls_socket.cipher()
                protocol = tls_socket.version()

    except (
        socket.timeout,
        socket.gaierror,
        ConnectionRefusedError,
        ssl.SSLError,
        OSError,
    ) as error:
        raise ValueError(
            f"TLS connection failed: {error}"
        ) from error

    subject = dict(
        item[0]
        for item in certificate.get(
            "subject",
            [],
        )
    )

    issuer = dict(
        item[0]
        for item in certificate.get(
            "issuer",
            [],
        )
    )

    common_name = subject.get(
        "commonName"
    )

    issuer_common_name = issuer.get(
        "commonName"
    )

    sans = [
        value
        for entry_type, value
        in certificate.get(
            "subjectAltName",
            [],
        )
        if entry_type == "DNS"
    ]

    not_before = _parse_certificate_date(
        certificate["notBefore"]
    )

    not_after = _parse_certificate_date(
        certificate["notAfter"]
    )

    days_remaining = _calculate_days_remaining(
        not_after
    )

    security_analysis = {
        "protocol": _analyze_protocol(
            protocol
        ),
        "cipher": _analyze_cipher(
            cipher
        ),
        "certificate": _analyze_certificate(
            days_remaining
        ),
        "hostname": _analyze_hostname(
            target,
            common_name,
            sans,
        ),
        "trust": _analyze_certificate_trust(
            trusted,
            verification_error,
        ),
    }

    security_score = calculate_tls_security_score(
        security_analysis
    )

    return {
        "target": target,
        "port": port,
        "protocol": protocol,
        "cipher": {
            "name": cipher[0],
            "protocol": cipher[1],
            "bits": cipher[2],
        },
        "certificate": {
            "common_name": common_name,
            "subject_alt_names": sans,
            "issuer": issuer_common_name,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": days_remaining,
            "expired": days_remaining < 0,
            "trusted": trusted,
            "verification_error": verification_error,
        },
        "security_analysis": security_analysis,
        "security_score": security_score,
    }