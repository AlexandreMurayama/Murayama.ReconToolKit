from html import escape
from pathlib import Path


def _html_list(items: list[str]) -> str:
    if not items:
        return "<p>No data available.</p>"

    list_items = "".join(
        f"<li>{escape(str(item))}</li>"
        for item in items
    )

    return f"<ul>{list_items}</ul>"


def _render_badge(
    text: str,
    badge_type: str | None = None,
) -> str:
    normalized = (
        badge_type
        or text
        or "info"
    ).lower()

    if normalized not in {
        "good",
        "high",
        "medium",
        "low",
        "info",
    }:
        normalized = "info"

    return (
        f'<span class="badge badge-{normalized}">'
        f'{escape(str(text).upper())}'
        f'</span>'
    )


def _render_security_headers(
    http_results: list[dict],
) -> str:
    if not http_results:
        return "<p>No HTTP results available.</p>"

    sections = []

    for result in http_results:
        headers = result.get(
            "security_headers",
            {},
        )

        score = result.get(
            "security_score",
            {},
        )

        rows = []

        for header, details in headers.items():
            status = details.get(
                "status",
                "unknown",
            ).upper()

            severity = details.get(
                "severity"
            ) or "-"

            status_badge_type = {
                "GOOD": "good",
                "WEAK": severity or "medium",
                "MISSING": severity or "info",
            }.get(
                status,
                "info",
            )

            status_html = _render_badge(
                status,
                status_badge_type,
            )

            severity_html = (
                _render_badge(
                    severity,
                    severity,
                )
                if severity != "-"
                else "-"
            )

            value = details.get(
                "value"
            ) or "-"

            issues = "<br>".join(
                escape(issue)
                for issue in details.get(
                    "issues",
                    [],
                )
            ) or "-"

            recommendation = (
                details.get(
                    "recommendation"
                )
                or "-"
            )

            rows.append(
                f"""
                <tr>
                    <td>{escape(header)}</td>
                    <td>{status_html}</td>
                    <td>{severity_html}</td>
                    <td>{escape(str(value))}</td>
                    <td>{issues}</td>
                    <td>{escape(str(recommendation))}</td>
                </tr>
                """
            )

        sections.append(
            f"""
            <h3>{escape(result.get("url", "HTTP target"))}</h3>

            <p>
                <strong>Security Score:</strong>
            </p>
            
            <div class="score {
                'score-good'
                if score.get('score', 0) >= 80
                else 'score-medium'
                if score.get('score', 0) >= 50
                else 'score-high'
            }">
                {score.get("score", "-")}/100
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Header</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Value</th>
                        <th>Issues</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
            """
        )

    return "".join(sections)


def _render_tls_results(
    tls_results: list[dict],
) -> str:
    if not tls_results:
        return "<p>No TLS results available.</p>"

    sections = []

    for result in tls_results:
        certificate = result.get(
            "certificate",
            {},
        )

        cipher = result.get(
            "cipher",
            {},
        )

        analysis = result.get(
            "security_analysis",
            {},
        )

        score = result.get(
            "security_score",
            {},
        )

        rows = []

        for check_name, details in analysis.items():
            status = details.get(
                "status",
                "unknown",
            ).upper()

            severity = details.get(
                "severity"
            ) or "-"

            status_badge_type = {
                "GOOD": "good",
                "WEAK": severity or "medium",
                "HIGH": "high",
                "UNKNOWN": "info",
            }.get(
                status,
                "info",
            )

            status_html = _render_badge(
                status,
                status_badge_type,
            )

            severity_html = (
                _render_badge(
                    severity,
                    severity,
                )
                if severity != "-"
                else "-"
            )

            issues = "<br>".join(
                escape(issue)
                for issue in details.get(
                    "issues",
                    [],
                )
            ) or "-"

            recommendation = (
                details.get(
                    "recommendation"
                )
                or "-"
            )

            rows.append(
                f"""
                <tr>
                    <td>{escape(check_name.capitalize())}</td>
                    <td>{status_html}</td>
                    <td>{severity_html}</td>
                    <td>{issues}</td>
                    <td>{escape(str(recommendation))}</td>
                </tr>
                """
            )

        sans = certificate.get(
            "subject_alt_names",
            [],
        )

        sections.append(
            f"""
            <h3>
                {escape(result.get("target", "TLS target"))}
                :
                {result.get("port", "-")}
            </h3>

            <p>
                <strong>Protocol:</strong>
                {escape(str(result.get("protocol", "-")))}
            </p>

            <p>
                <strong>Cipher:</strong>
                {escape(str(cipher.get("name", "-")))}
                ({escape(str(cipher.get("bits", "-")))} bits)
            </p>

            <p>
                <strong>Common Name:</strong>
                {escape(str(certificate.get("common_name", "-")))}
            </p>

            <p>
                <strong>Issuer:</strong>
                {escape(str(certificate.get("issuer", "-")))}
            </p>

            <p>
                <strong>Valid Until:</strong>
                {escape(str(certificate.get("not_after", "-")))}
            </p>

            <p>
                <strong>Days Remaining:</strong>
                {escape(str(certificate.get("days_remaining", "-")))}
            </p>

            <p>
                <strong>SANs:</strong>
            </p>

            {_html_list(sans)}

            <p>
                <strong>TLS Security Score:</strong>
            </p>
            
            <div class="score {
                'score-good'
                if score.get('score', 0) >= 80
                else 'score-medium'
                if score.get('score', 0) >= 50
                else 'score-high'
            }">
                {score.get("score", "-")}/100
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Check</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Issues</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
            """
        )

    return "".join(sections)


def _build_security_findings(
    recon_results: dict,
) -> list[dict]:
    findings_by_key = {}

    # HTTP Security Header findings
    for http_result in recon_results.get(
        "http",
        [],
    ):
        asset = http_result.get(
            "url",
            "unknown",
        )

        security_headers = http_result.get(
            "security_headers",
            {},
        )

        for header_name, details in security_headers.items():
            status = details.get(
                "status",
                "unknown",
            )

            if status == "good":
                continue

            severity = (
                details.get("severity")
                or "info"
            )

            finding_key = (
                "http-header",
                header_name,
                status,
                severity,
            )

            # Finding already exists:
            # add another affected asset.
            if finding_key in findings_by_key:
                existing = findings_by_key[
                    finding_key
                ]

                if asset not in existing["assets"]:
                    existing["assets"].append(
                        asset
                    )

                continue

            issues = details.get(
                "issues",
                [],
            )

            description = (
                issues[0]
                if issues
                else (
                    f"{header_name} "
                    "security issue detected."
                )
            )

            findings_by_key[finding_key] = {
                "source": "HTTP",
                "severity": severity,
                "finding": header_name,
                "assets": [asset],
                "status": status,
                "description": description,
                "recommendation": (
                    details.get(
                        "recommendation"
                    )
                    or "-"
                ),
            }

    # TLS findings
    for tls_result in recon_results.get(
        "tls",
        [],
    ):
        target = tls_result.get(
            "target",
            "unknown",
        )

        port = tls_result.get(
            "port",
            443,
        )

        asset = f"{target}:{port}"

        security_analysis = tls_result.get(
            "security_analysis",
            {},
        )

        for check_name, details in security_analysis.items():
            status = details.get(
                "status",
                "unknown",
            )

            if status == "good":
                continue

            severity = (
                details.get("severity")
                or "info"
            )

            finding_key = (
                "tls",
                check_name,
                status,
                severity,
            )

            if finding_key in findings_by_key:
                existing = findings_by_key[
                    finding_key
                ]

                if asset not in existing["assets"]:
                    existing["assets"].append(
                        asset
                    )

                continue

            issues = details.get(
                "issues",
                [],
            )

            description = (
                issues[0]
                if issues
                else (
                    f"{check_name} "
                    "TLS issue detected."
                )
            )

            findings_by_key[finding_key] = {
                "source": "TLS",
                "severity": severity,
                "finding": check_name.capitalize(),
                "assets": [asset],
                "status": status,
                "description": description,
                "recommendation": (
                    details.get(
                        "recommendation"
                    )
                    or "-"
                ),
            }

    findings = list(
        findings_by_key.values()
    )

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    findings.sort(
        key=lambda finding: severity_order.get(
            finding["severity"].lower(),
            99,
        )
    )

    counters = {
        "HTTP": 0,
        "TLS": 0,
    }

    for finding in findings:
        source = finding.get(
            "source",
            "UNKNOWN",
        ).upper()

        if source not in counters:
            counters[source] = 0

        counters[source] += 1

        finding["id"] = (
            f"MR-{source}-"
            f"{counters[source]:03d}"
        )

    return findings


def _render_affected_assets(
    assets: list[str],
) -> str:
    if not assets:
        return "-"

    items = []

    for asset in assets:
        items.append(
            f"<li>{escape(str(asset))}</li>"
        )

    return (
        '<ul class="affected-assets">'
        f'{"".join(items)}'
        "</ul>"
    )


def _render_security_findings(
    findings: list[dict],
) -> str:
    if not findings:
        return """
        <div class="no-findings">
            No security findings were identified
            by the executed checks.
        </div>
        """

    rows = []

    for finding in findings:
        severity = finding.get(
            "severity",
            "info",
        )

        status = finding.get(
            "status",
            "unknown",
        )

        severity_html = _render_badge(
            severity,
            severity,
        )

        status_badge_type = {
            "good": "good",
            "weak": severity,
            "missing": severity,
            "high": "high",
            "unknown": "info",
        }.get(
            status.lower(),
            "info",
        )

        status_html = _render_badge(
            status,
            status_badge_type,
        )

        assets_html = _render_affected_assets(
            finding.get(
                "assets",
                [],
            )
        )

        rows.append(
            f"""
           <tr>
                <td>
                    <code class="finding-id">
                        {escape(str(finding.get("id", "-")))}
                    </code>
                </td>
            
                <td>{severity_html}</td>
            
                <td>
                    <strong>
                        {escape(str(finding["finding"]))}
                    </strong>

                    <div class="finding-source">
                        {escape(str(finding["source"]))}
                    </div>
                </td>

                <td>
                    {assets_html}
                </td>

                <td>
                    {status_html}
                </td>

                <td>
                    {escape(str(finding["description"]))}
                </td>

                <td>
                    {escape(str(finding["recommendation"]))}
                </td>
            </tr>
            """
        )

    return f"""
    <table class="findings-table">
        <thead>
            <tr>
                <th>ID</th>
                <th>Severity</th>
                <th>Finding</th>
                <th>Affected Assets</th>
                <th>Status</th>
                <th>Description</th>
                <th>Recommendation</th>
            </tr>
        </thead>

        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def _build_executive_summary(
    recon_results: dict,
) -> dict:
    summary = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "good": 0,
        "total_findings": 0,
    }

    seen_http_findings = set()

    # HTTP Security Headers
    for http_result in recon_results.get(
        "http",
        [],
    ):
        security_headers = http_result.get(
            "security_headers",
            {},
        )

        for header_name, details in security_headers.items():
            status = details.get(
                "status",
                "unknown",
            )

            severity = details.get(
                "severity",
            )

            if status == "good":
                continue

            # The same header finding may appear on
            # both HTTP and HTTPS responses.
            finding_key = (
                header_name,
                status,
                severity,
            )

            if finding_key in seen_http_findings:
                continue

            seen_http_findings.add(
                finding_key
            )

            summary["total_findings"] += 1

            if severity in (
                "high",
                "medium",
                "low",
            ):
                summary[severity] += 1
            else:
                summary["info"] += 1

    # TLS Security Analysis
    for tls_result in recon_results.get(
        "tls",
        [],
    ):
        security_analysis = tls_result.get(
            "security_analysis",
            {},
        )

        for details in security_analysis.values():
            status = details.get(
                "status",
                "unknown",
            )

            severity = details.get(
                "severity",
            )

            if status == "good":
                summary["good"] += 1
                continue

            summary["total_findings"] += 1

            if severity in (
                "high",
                "medium",
                "low",
            ):
                summary[severity] += 1
            else:
                summary["info"] += 1

    return summary


def _render_dns_results(
    dns_results,
) -> str:
    if not dns_results:
        return "<p>No DNS results available.</p>"

    rows = []

    # Expected structure:
    #
    # {
    #     "A": [...],
    #     "AAAA": [...],
    #     "MX": [...],
    #     "NS": [...],
    #     "TXT": [...]
    # }

    if isinstance(dns_results, dict):
        for record_type, values in dns_results.items():

            if not isinstance(values, list):
                values = [values]

            for value in values:
                rows.append(
                    f"""
                    <tr>
                        <td>
                            {escape(str(record_type))}
                        </td>
                        <td>
                            {escape(str(value))}
                        </td>
                    </tr>
                    """
                )

    # Compatibility fallback
    elif isinstance(dns_results, list):
        for result in dns_results:

            if isinstance(result, dict):
                record_type = result.get(
                    "type",
                    "unknown",
                )

                value = result.get(
                    "value",
                    "-",
                )

            else:
                record_type = "unknown"
                value = result

            rows.append(
                f"""
                <tr>
                    <td>
                        {escape(str(record_type))}
                    </td>
                    <td>
                        {escape(str(value))}
                    </td>
                </tr>
                """
            )

    if not rows:
        return "<p>No DNS results available.</p>"

    return f"""
    <table>
        <thead>
            <tr>
                <th>Record Type</th>
                <th>Value</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def _render_subdomains(
    subdomains: list,
) -> str:
    if not subdomains:
        return "<p>No subdomains discovered.</p>"

    items = []

    for result in subdomains:
        if isinstance(result, dict):
            name = (
                result.get("subdomain")
                or result.get("host")
                or result.get("name")
                or str(result)
            )
        else:
            name = str(result)

        items.append(name)

    return _html_list(items)


def _render_banners(
    banners: list[dict],
) -> str:
    if not banners:
        return "<p>No service banners received.</p>"

    rows = []

    for result in banners:
        port = result.get(
            "port",
            "-",
        )

        banner = result.get(
            "banner",
            "-",
        )

        rows.append(
            f"""
            <tr>
                <td>{escape(str(port))}/tcp</td>
                <td><pre>{escape(str(banner))}</pre></td>
            </tr>
            """
        )

    return f"""
    <table>
        <thead>
            <tr>
                <th>Port</th>
                <th>Banner</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def _render_nmap_results(
    nmap_results: list[dict],
) -> str:
    if not nmap_results:
        return "<p>No Nmap enrichment results available.</p>"

    rows = []

    for result in nmap_results:
        port = result.get(
            "port",
            "-",
        )

        service = result.get(
            "service",
            "unknown",
        )

        product = result.get(
            "product",
            "-",
        )

        version = result.get(
            "version",
            "-",
        )

        rows.append(
            f"""
            <tr>
                <td>{escape(str(port))}/tcp</td>
                <td>{escape(str(service))}</td>
                <td>{escape(str(product))}</td>
                <td>{escape(str(version))}</td>
            </tr>
            """
        )

    return f"""
    <table>
        <thead>
            <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Product</th>
                <th>Version</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def generate_html_report(
    recon_results: dict,
    output_path: str,
) -> None:
    output = Path(
        output_path
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    target = recon_results.get(
        "target",
        "unknown",
    )

    generated_at = recon_results.get(
        "generated_at",
        "unknown",
    )

    summary = _build_executive_summary(
        recon_results
    )

    findings = _build_security_findings(
        recon_results
    )

    ports = recon_results.get(
        "ports",
        [],
    )

    port_items = [
        (
            f"{result.get('port')}/tcp "
            f"{result.get('service', 'unknown')}"
        )
        for result in ports
    ]

    html = f"""
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>
        MurayamaRecon Security Report - {escape(str(target))}
    </title>

    <style>
        :root {{
            --bg: #f4f6f8;
            --surface: #ffffff;
            --surface-alt: #f8fafc;
            --text: #172033;
            --muted: #64748b;
            --border: #e2e8f0;
    
            --primary: #172033;
    
            --high: #dc2626;
            --medium: #d97706;
            --low: #2563eb;
            --info: #64748b;
            --good: #15803d;
        }}
    
        * {{
            box-sizing: border-box;
        }}
    
        body {{
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font-family:
                Inter,
                "Segoe UI",
                Arial,
                sans-serif;
            line-height: 1.5;
        }}
    
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px;
        }}
    
        .report-header {{
            background: var(--primary);
            color: white;
            padding: 32px 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
    
        .report-header h1 {{
            margin: 0;
            font-size: 32px;
        }}
    
        .report-header .subtitle {{
            margin-top: 6px;
            color: #cbd5e1;
        }}
    
        h2 {{
            margin-top: 42px;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 2px solid var(--border);
            font-size: 22px;
        }}
    
        h3 {{
            margin-top: 28px;
            font-size: 17px;
        }}
    
        .summary {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(220px, 1fr));
            gap: 15px;
    
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
    
        .summary p {{
            margin: 0;
        }}
    
        .summary strong {{
            display: block;
            color: var(--muted);
            font-size: 12px;
            text-transform: uppercase;
            margin-bottom: 4px;
        }}
    
        .cards {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(130px, 1fr));
            gap: 15px;
            margin: 20px 0 30px 0;
        }}
    
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px;
            text-align: center;
            border-top: 4px solid var(--info);
        }}
    
        .card.high {{
            border-top-color: var(--high);
        }}
    
        .card.medium {{
            border-top-color: var(--medium);
        }}
    
        .card.low {{
            border-top-color: var(--low);
        }}
    
        .card.info {{
            border-top-color: var(--info);
        }}
    
        .card.good {{
            border-top-color: var(--good);
        }}
    
        .card-value {{
            font-size: 30px;
            font-weight: 700;
        }}
    
        .card-label {{
            margin-top: 4px;
            color: var(--muted);
            font-size: 13px;
        }}
    
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border: 1px solid var(--border);
            margin: 15px 0 30px 0;
            font-size: 14px;
        }}
    
        th {{
            background: var(--surface-alt);
            color: var(--text);
            font-weight: 600;
        }}
    
        th,
        td {{
            padding: 11px 12px;
            border-bottom: 1px solid var(--border);
            text-align: left;
            vertical-align: top;
        }}
    
        tr:last-child td {{
            border-bottom: none;
        }}
    
        tr:hover {{
            background: var(--surface-alt);
        }}
    
        pre {{
            margin: 0;
            padding: 14px;
            overflow-x: auto;
    
            background: #111827;
            color: #e5e7eb;
    
            border-radius: 6px;
    
            font-family:
                "Cascadia Code",
                Consolas,
                monospace;
    
            font-size: 13px;
        }}
    
        code {{
            font-family:
                "Cascadia Code",
                Consolas,
                monospace;
        }}
    
        ul {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 15px 15px 15px 36px;
        }}
    
        .score {{
            display: inline-block;
            margin: 8px 0 15px 0;
            padding: 7px 12px;
            border-radius: 6px;
            font-weight: 700;
        }}
    
        .score-good {{
            color: var(--good);
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
        }}
    
        .score-medium {{
            color: var(--medium);
            background: #fffbeb;
            border: 1px solid #fde68a;
        }}
    
        .score-high {{
            color: var(--high);
            background: #fef2f2;
            border: 1px solid #fecaca;
        }}
    
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
    
        .badge-good {{
            background: #dcfce7;
            color: var(--good);
        }}
    
        .badge-high {{
            background: #fee2e2;
            color: var(--high);
        }}
    
        .badge-medium {{
            background: #fef3c7;
            color: var(--medium);
        }}
    
        .badge-low {{
            background: #dbeafe;
            color: var(--low);
        }}
    
        .badge-info {{
            background: #e2e8f0;
            color: var(--info);
        }}
    
        .footer {{
            margin-top: 50px;
            padding: 20px 0;
            border-top: 1px solid var(--border);
            color: var(--muted);
            font-size: 12px;
            text-align: center;
        }}
    
        @media (max-width: 700px) {{
            .container {{
                padding: 20px;
            }}
    
            .report-header {{
                padding: 24px;
            }}
    
            table {{
                display: block;
                overflow-x: auto;
            }}
        }}
        
        .finding-source {{
            margin-top: 3px;
            color: var(--muted);
            font-size: 11px;
            text-transform: uppercase;
        }}
        
        .findings-table td:nth-child(1),
        .findings-table td:nth-child(2),
        .findings-table td:nth-child(5) {{
            white-space: nowrap;
        }}
        
        .no-findings {{
            padding: 18px;
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 8px;
            color: var(--good);
        }}
        
        .affected-assets {{
            margin: 0;
            padding: 0;
            border: none;
            background: transparent;
            list-style: none;
        }}
        
        .affected-assets li {{
            margin-bottom: 4px;
            font-family:
                "Cascadia Code",
                Consolas,
                monospace;
            font-size: 12px;
        }}
        
        .affected-assets li:last-child {{
            margin-bottom: 0;
        }}
        .finding-id {{
            white-space: nowrap;
            font-family:
                "Cascadia Code",
                Consolas,
                monospace;
            font-size: 12px;
            font-weight: 600;
            color: var(--text);
        }}
    </style>
</head>

<body>

<div class="container">

    <header class="report-header">
        <h1>MurayamaRecon</h1>

        <div class="subtitle">
            Security Reconnaissance & Assessment Report
        </div>
    </header>

    <div class="summary">
        <p>
            <strong>Target:</strong>
            {escape(str(target))}
        </p>

        <p>
            <strong>Generated at:</strong>
            {escape(str(generated_at))}
        </p>

        <p>
            <strong>Tool:</strong>
            Murayama Recon Automation Toolkit
        </p>
    </div>

    <h2>Executive Summary</h2>

    <div class="cards">

        <div class="card">
            <div class="card-value">
                {summary["total_findings"]}
            </div>
            <div class="card-label">
                Findings
            </div>
        </div>

        <div class="card high">
            <div class="card-value">
                {summary["high"]}
            </div>
            <div class="card-label">
                High
            </div>
        </div>

        <div class="card medium">
            <div class="card-value">
                {summary["medium"]}
            </div>
            <div class="card-label">
                Medium
            </div>
        </div>

        <div class="card low">
            <div class="card-value">
                {summary["low"]}
            </div>
            <div class="card-label">
                Low
            </div>
        </div>

        <div class="card info">
            <div class="card-value">
                {summary["info"]}
            </div>
            <div class="card-label">
                Informational
            </div>
        </div>

        <div class="card good">
            <div class="card-value">
                {summary["good"]}
            </div>
            <div class="card-label">
                Passed Checks
            </div>
        </div>

    </div>
    
    <h2>Security Findings</h2>

    {_render_security_findings(
        findings
    )}

    <h2>DNS Reconnaissance</h2>

    {_render_dns_results(
        recon_results.get(
            "dns",
            [],
        )
    )}

    <h2>Subdomain Discovery</h2>

    {_render_subdomains(
        recon_results.get(
            "subdomains",
            [],
        )
    )}

    <h2>Open Ports</h2>

    {_html_list(port_items)}

    <h2>Banner Grabbing</h2>

    {_render_banners(
        recon_results.get(
            "banners",
            [],
        )
    )}

    <h2>Nmap Service Enrichment</h2>

    {_render_nmap_results(
        recon_results.get(
            "nmap",
            [],
        )
    )}

    <h2>HTTP Security Header Analysis</h2>

    {_render_security_headers(
        recon_results.get(
            "http",
            [],
        )
    )}

    <h2>TLS/SSL Security Analysis</h2>

    {_render_tls_results(
        recon_results.get(
            "tls",
            [],
        )
    )}
</div>

</body>
</html>
"""

    output.write_text(
        html,
        encoding="utf-8",
    )