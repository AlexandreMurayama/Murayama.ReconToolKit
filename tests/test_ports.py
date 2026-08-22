import pytest

from recon import ports


def test_scan_port_returns_none_for_closed_port(monkeypatch):
    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            pass

        def settimeout(self, timeout):
            pass

        def connect_ex(self, address):
            return 1

    monkeypatch.setattr(
        ports.socket,
        "socket",
        lambda *args, **kwargs: FakeSocket(),
    )

    result = ports.scan_port(
        target="localhost",
        port=12345,
        timeout=1.0,
    )

    assert result is None


def test_scan_port_returns_open_port(monkeypatch):
    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            pass

        def settimeout(self, timeout):
            pass

        def connect_ex(self, address):
            return 0

    monkeypatch.setattr(
        ports.socket,
        "socket",
        lambda *args, **kwargs: FakeSocket(),
    )

    result = ports.scan_port(
        target="localhost",
        port=8080,
        timeout=1.0,
    )

    assert result == {
        "port": 8080,
        "service": "http-alt",
    }


def test_scan_ports_raises_error_for_invalid_hostname(monkeypatch):
    def fake_gethostbyname(target):
        raise ports.socket.gaierror()

    monkeypatch.setattr(
        ports.socket,
        "gethostbyname",
        fake_gethostbyname,
    )

    with pytest.raises(
        ValueError,
        match="Unable to resolve target: invalid.local",
    ):
        ports.scan_ports(
            target="invalid.local",
            ports=[80],
            threads=1,
            timeout=1.0,
        )