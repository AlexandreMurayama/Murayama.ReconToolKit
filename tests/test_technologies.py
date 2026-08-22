from recon.technologies import (
    analyze_security_headers,
    analyze_technologies,
)


def test_analyze_technologies_detects_server_and_powered_by():
    headers = {
        "Server": "nginx",
        "X-Powered-By": "ASP.NET",
    }

    result = analyze_technologies(headers)

    assert result["server"] == "nginx"
    assert result["powered_by"] == "ASP.NET"


def test_security_headers_present():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
    }

    result = analyze_security_headers(headers)

    assert result["Strict-Transport-Security"]["present"] is True
    assert (
        result["Strict-Transport-Security"]["value"]
        == "max-age=31536000"
    )

    assert result["X-Content-Type-Options"]["present"] is True


def test_security_headers_missing():
    headers = {}

    result = analyze_security_headers(headers)

    assert result["Content-Security-Policy"]["present"] is False
    assert result["Content-Security-Policy"]["value"] is None