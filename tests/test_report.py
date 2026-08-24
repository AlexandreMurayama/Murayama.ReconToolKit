from pathlib import Path

from recon.report import (
    _build_executive_summary,
    _build_security_findings,
    _render_affected_assets,
    generate_html_report,
)


def _build_test_results() -> dict:
    return {
        "target": "example.com",
        "generated_at": "2026-08-24T12:00:00",
        "ports": [],
        "dns": {},
        "subdomains": [],
        "banners": [],
        "nmap": [],
        "http": [
            {
                "url": "http://example.com/",
                "security_headers": {
                    "Content-Security-Policy": {
                        "status": "missing",
                        "severity": "medium",
                        "issues": [
                            "Security header is missing."
                        ],
                        "recommendation": (
                            "Define a restrictive Content "
                            "Security Policy."
                        ),
                    },
                    "X-Content-Type-Options": {
                        "status": "missing",
                        "severity": "low",
                        "issues": [
                            "Security header is missing."
                        ],
                        "recommendation": (
                            "Set X-Content-Type-Options "
                            "to nosniff."
                        ),
                    },
                },
                "security_score": {
                    "score": 0,
                    "good": 0,
                    "weak": 0,
                    "missing": 2,
                },
            },
            {
                "url": "https://example.com/",
                "security_headers": {
                    "Content-Security-Policy": {
                        "status": "missing",
                        "severity": "medium",
                        "issues": [
                            "Security header is missing."
                        ],
                        "recommendation": (
                            "Define a restrictive Content "
                            "Security Policy."
                        ),
                    },
                    "X-Content-Type-Options": {
                        "status": "missing",
                        "severity": "low",
                        "issues": [
                            "Security header is missing."
                        ],
                        "recommendation": (
                            "Set X-Content-Type-Options "
                            "to nosniff."
                        ),
                    },
                },
                "security_score": {
                    "score": 0,
                    "good": 0,
                    "weak": 0,
                    "missing": 2,
                },
            },
        ],
        "tls": [
            {
                "target": "example.com",
                "port": 443,
                "protocol": "TLSv1.3",
                "cipher": {
                    "name": "TLS_AES_256_GCM_SHA384",
                    "bits": 256,
                },
                "certificate": {
                    "common_name": "example.com",
                    "issuer": "Test CA",
                    "not_before": "2026-08-01",
                    "not_after": "2026-11-01",
                    "days_remaining": 69,
                    "expired": False,
                    "subject_alt_names": [
                        "example.com",
                    ],
                },
                "security_analysis": {
                    "protocol": {
                        "status": "good",
                        "severity": None,
                        "issues": [],
                        "recommendation": None,
                    },
                    "cipher": {
                        "status": "good",
                        "severity": None,
                        "issues": [],
                        "recommendation": None,
                    },
                    "certificate": {
                        "status": "good",
                        "severity": None,
                        "issues": [],
                        "recommendation": None,
                    },
                    "hostname": {
                        "status": "good",
                        "severity": None,
                        "issues": [],
                        "recommendation": None,
                    },
                    "trust": {
                        "status": "good",
                        "severity": None,
                        "issues": [],
                        "recommendation": None,
                    },
                },
                "security_score": {
                    "score": 100,
                    "good": 5,
                    "weak": 0,
                    "high": 0,
                    "unknown": 0,
                },
            }
        ],
    }


def test_executive_summary_deduplicates_http_findings():
    results = _build_test_results()

    summary = _build_executive_summary(
        results
    )

    assert summary["total_findings"] == 2
    assert summary["medium"] == 1
    assert summary["low"] == 1
    assert summary["high"] == 0
    assert summary["good"] == 5


def test_security_findings_consolidate_affected_assets():
    results = _build_test_results()

    findings = _build_security_findings(
        results
    )

    assert len(findings) == 2

    csp = next(
        finding
        for finding in findings
        if finding["finding"]
        == "Content-Security-Policy"
    )

    assert csp["assets"] == [
        "http://example.com/",
        "https://example.com/",
    ]


def test_security_findings_generate_ids():
    results = _build_test_results()

    findings = _build_security_findings(
        results
    )

    assert findings[0]["id"] == "MR-HTTP-001"
    assert findings[1]["id"] == "MR-HTTP-002"


def test_affected_assets_escape_html():
    html = _render_affected_assets(
        [
            "<script>alert('xss')</script>",
        ]
    )

    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_generate_html_report(tmp_path: Path):
    results = _build_test_results()

    report_path = (
        tmp_path
        / "report.html"
    )

    generate_html_report(
        results,
        str(report_path),
    )

    assert report_path.exists()

    html = report_path.read_text(
        encoding="utf-8"
    )

    assert "MurayamaRecon" in html
    assert "Executive Summary" in html
    assert "Security Findings" in html
    assert "MR-HTTP-001" in html
    assert "Content-Security-Policy" in html
    assert "http://example.com/" in html
    assert "https://example.com/" in html
    assert "TLS/SSL Security Analysis" in html