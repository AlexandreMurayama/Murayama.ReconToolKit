from recon.tls import (
    _analyze_certificate,
    _analyze_certificate_trust,
    _analyze_cipher,
    _analyze_hostname,
    _analyze_protocol,
    _hostname_matches,
    calculate_tls_security_score,
)


def test_tls13_protocol_is_good():
    result = _analyze_protocol("TLSv1.3")

    assert result["status"] == "good"
    assert result["severity"] is None
    assert result["issues"] == []
    assert result["recommendation"] is None


def test_tls12_protocol_is_good():
    result = _analyze_protocol("TLSv1.2")

    assert result["status"] == "good"


def test_legacy_tls_protocol_is_weak():
    result = _analyze_protocol("TLSv1")

    assert result["status"] == "weak"
    assert result["severity"] == "high"
    assert any(
        "Deprecated TLS/SSL protocol negotiated"
        in issue
        for issue in result["issues"]
    )


def test_unknown_protocol_is_unknown():
    result = _analyze_protocol("TLSv9.9")

    assert result["status"] == "unknown"
    assert result["severity"] == "info"


def test_modern_cipher_is_good():
    result = _analyze_cipher(
        (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        )
    )

    assert result["status"] == "good"
    assert result["severity"] is None


def test_weak_cipher_name_is_detected():
    result = _analyze_cipher(
        (
            "RC4-SHA",
            "TLSv1",
            128,
        )
    )

    assert result["status"] == "weak"
    assert result["severity"] == "high"
    assert any(
        "Potentially weak cipher detected"
        in issue
        for issue in result["issues"]
    )


def test_low_bit_cipher_is_detected():
    result = _analyze_cipher(
        (
            "TEST-CIPHER",
            "TLSv1.2",
            64,
        )
    )

    assert result["status"] == "weak"
    assert any(
        "Cipher strength is only 64 bits."
        in issue
        for issue in result["issues"]
    )


def test_valid_certificate_is_good():
    result = _analyze_certificate(90)

    assert result["status"] == "good"
    assert result["severity"] is None


def test_certificate_expiring_within_30_days_is_weak():
    result = _analyze_certificate(20)

    assert result["status"] == "weak"
    assert result["severity"] == "medium"
    assert any(
        "Certificate expires in 20 days."
        in issue
        for issue in result["issues"]
    )


def test_certificate_expiring_within_7_days_is_high_priority():
    result = _analyze_certificate(5)

    assert result["status"] == "weak"
    assert result["severity"] == "high"
    assert any(
        "Certificate expires in 5 days."
        in issue
        for issue in result["issues"]
    )


def test_expired_certificate_is_high():
    result = _analyze_certificate(-14)

    assert result["status"] == "high"
    assert result["severity"] == "high"
    assert any(
        "Certificate expired 14 days ago."
        in issue
        for issue in result["issues"]
    )


def test_exact_hostname_match():
    assert _hostname_matches(
        "example.com",
        "example.com",
    ) is True


def test_hostname_match_is_case_insensitive():
    assert _hostname_matches(
        "EXAMPLE.COM",
        "example.com",
    ) is True


def test_wildcard_hostname_match():
    assert _hostname_matches(
        "www.example.com",
        "*.example.com",
    ) is True


def test_wildcard_does_not_match_base_domain():
    assert _hostname_matches(
        "example.com",
        "*.example.com",
    ) is False


def test_wildcard_does_not_match_multiple_levels():
    assert _hostname_matches(
        "api.dev.example.com",
        "*.example.com",
    ) is False


def test_hostname_analysis_uses_san():
    result = _analyze_hostname(
        target="api.example.com",
        common_name="legacy.example.com",
        sans=["api.example.com"],
    )

    assert result["status"] == "good"


def test_hostname_analysis_uses_cn_as_fallback():
    result = _analyze_hostname(
        target="example.com",
        common_name="example.com",
        sans=[],
    )

    assert result["status"] == "good"


def test_hostname_mismatch_is_high():
    result = _analyze_hostname(
        target="example.com",
        common_name="other.example.net",
        sans=["other.example.net"],
    )

    assert result["status"] == "high"
    assert result["severity"] == "high"
    assert any(
        "Certificate does not match target hostname"
        in issue
        for issue in result["issues"]
    )


def test_tls_security_score_all_good():
    analysis = {
        "protocol": {
            "status": "good",
        },
        "cipher": {
            "status": "good",
        },
        "certificate": {
            "status": "good",
        },
        "hostname": {
            "status": "good",
        },
    }

    score = calculate_tls_security_score(
        analysis
    )

    assert score["score"] == 100
    assert score["good"] == 4
    assert score["weak"] == 0
    assert score["high"] == 0
    assert score["unknown"] == 0


def test_tls_security_score_mixed():
    analysis = {
        "protocol": {
            "status": "good",
        },
        "cipher": {
            "status": "weak",
        },
        "certificate": {
            "status": "high",
        },
        "hostname": {
            "status": "unknown",
        },
    }

    score = calculate_tls_security_score(
        analysis
    )

    assert score["good"] == 1
    assert score["weak"] == 1
    assert score["high"] == 1
    assert score["unknown"] == 1
    assert score["score"] == 44

    def test_certificate_trust_valid():
        result = _analyze_certificate_trust(
            trusted=True,
            verification_error=None,
        )

        assert result["status"] == "good"
        assert result["severity"] is None
        assert result["issues"] == []
        assert result["recommendation"] is None

    def test_certificate_trust_self_signed_is_high():
        result = _analyze_certificate_trust(
            trusted=False,
            verification_error=(
                "certificate verify failed: "
                "self-signed certificate"
            ),
        )

        assert result["status"] == "high"
        assert result["severity"] == "high"

        assert any(
            "self-signed certificate" in issue
            for issue in result["issues"]
        )

        assert result["recommendation"] is not None

    def test_tls_security_score_with_trust_failure():
        analysis = {
            "protocol": {
                "status": "good",
            },
            "cipher": {
                "status": "good",
            },
            "certificate": {
                "status": "weak",
            },
            "hostname": {
                "status": "good",
            },
            "trust": {
                "status": "high",
            },
        }

        score = calculate_tls_security_score(
            analysis
        )

        assert score["score"] == 70
        assert score["good"] == 3
        assert score["weak"] == 1
        assert score["high"] == 1
        assert score["unknown"] == 0