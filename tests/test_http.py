from recon.http import _extract_title


def test_extract_title():
    html = """
    <html>
        <head>
            <title>Murayama Recon Toolkit</title>
        </head>
    </html>
    """

    assert _extract_title(html) == "Murayama Recon Toolkit"


def test_extract_title_normalizes_whitespace():
    html = """
    <title>
        Murayama
        Recon Toolkit
    </title>
    """

    assert _extract_title(html) == "Murayama Recon Toolkit"


def test_extract_title_returns_none_when_missing():
    html = "<html><body>Hello</body></html>"

    assert _extract_title(html) is None