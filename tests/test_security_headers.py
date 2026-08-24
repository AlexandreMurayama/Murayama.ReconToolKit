from recon.security_headers import (
    analyze_security_headers,
    calculate_security_score,
)


def test_valid_security_headers_are_good():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=()",
    }

    results = analyze_security_headers(headers)

    assert results["Strict-Transport-Security"]["status"] == "good"
    assert results["Content-Security-Policy"]["status"] == "good"
    assert results["X-Frame-Options"]["status"] == "good"
    assert results["X-Content-Type-Options"]["status"] == "good"
    assert results["Referrer-Policy"]["status"] == "good"
    assert results["Permissions-Policy"]["status"] == "good"


def test_missing_header_is_reported():
    results = analyze_security_headers({})

    hsts = results["Strict-Transport-Security"]

    assert hsts["present"] is False
    assert hsts["status"] == "missing"
    assert hsts["severity"] == "medium"
    assert "Security header is missing." in hsts["issues"]
    assert hsts["recommendation"] is not None


def test_x_frame_options_weak_value():
    results = analyze_security_headers(
        {
            "X-Frame-Options": "ALLOWALL",
        }
    )

    header = results["X-Frame-Options"]

    assert header["present"] is True
    assert header["status"] == "weak"
    assert header["severity"] == "medium"
    assert "Expected DENY or SAMEORIGIN." in header["issues"]


def test_x_content_type_options_invalid_value():
    results = analyze_security_headers(
        {
            "X-Content-Type-Options": "invalid",
        }
    )

    header = results["X-Content-Type-Options"]

    assert header["status"] == "weak"
    assert header["severity"] == "low"
    assert "Expected value 'nosniff'." in header["issues"]


def test_hsts_without_max_age_is_weak():
    results = analyze_security_headers(
        {
            "Strict-Transport-Security": "includeSubDomains",
        }
    )

    header = results["Strict-Transport-Security"]

    assert header["status"] == "weak"
    assert "Missing max-age directive." in header["issues"]


def test_csp_detects_unsafe_inline():
    results = analyze_security_headers(
        {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
        }
    )

    header = results["Content-Security-Policy"]

    assert header["status"] == "weak"
    assert "unsafe-inline directive detected." in header["issues"]


def test_csp_detects_unsafe_eval():
    results = analyze_security_headers(
        {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-eval'",
        }
    )

    header = results["Content-Security-Policy"]

    assert header["status"] == "weak"
    assert "unsafe-eval directive detected." in header["issues"]


def test_csp_detects_wildcard_source():
    results = analyze_security_headers(
        {
            "Content-Security-Policy": "default-src *",
        }
    )

    header = results["Content-Security-Policy"]

    assert header["status"] == "weak"
    assert "Wildcard source detected." in header["issues"]


def test_security_score_all_good():
    results = analyze_security_headers(
        {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "geolocation=()",
        }
    )

    score = calculate_security_score(results)

    assert score["score"] == 100
    assert score["good"] == 6
    assert score["weak"] == 0
    assert score["missing"] == 0


def test_security_score_mixed_results():
    results = analyze_security_headers(
        {
            "X-Frame-Options": "SAMEORIGIN",
            "Content-Security-Policy": "default-src *",
        }
    )

    score = calculate_security_score(results)

    assert score["good"] == 1
    assert score["weak"] == 1
    assert score["missing"] == 4
    assert score["score"] == 25


def test_header_lookup_is_case_insensitive():
    results = analyze_security_headers(
        {
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
        }
    )

    assert results["X-Frame-Options"]["status"] == "good"
    assert results["X-Content-Type-Options"]["status"] == "good"