import socket
import threading

import pytest

import recon.banner_grabber as banner_grabber


def test_decode_banner_valid():
    result = banner_grabber._decode_banner(
        b"SSH-2.0-OpenSSH_9.6\r\n"
    )

    assert result == "SSH-2.0-OpenSSH_9.6"


def test_decode_banner_empty():
    assert banner_grabber._decode_banner(b"") is None


def test_build_http_probe():
    probe = banner_grabber._build_http_probe(
        "example.com"
    )

    text = probe.decode("utf-8")

    assert "HEAD / HTTP/1.1\r\n" in text
    assert "Host: example.com\r\n" in text
    assert "User-Agent: MurayamaRecon/0.1.0\r\n" in text
    assert "Connection: close\r\n" in text
    assert text.endswith("\r\n\r\n")


def test_grab_banner_returns_none_on_connection_refused(
    monkeypatch,
):
    def fake_grab_tcp_banner(
        target: str,
        port: int,
        timeout: float,
    ):
        raise ConnectionRefusedError

    monkeypatch.setattr(
        banner_grabber,
        "_grab_tcp_banner",
        fake_grab_tcp_banner,
    )

    result = banner_grabber.grab_banner(
        target="localhost",
        port=65000,
        timeout=0.1,
    )

    assert result is None


def test_grab_banners_sorts_results_by_port(
    monkeypatch,
):
    def fake_grab_banner(
        target: str,
        port: int,
        timeout: float = 2.0,
    ):
        return {
            "port": port,
            "protocol": "tcp",
            "banner": f"banner-{port}",
        }

    monkeypatch.setattr(
        banner_grabber,
        "grab_banner",
        fake_grab_banner,
    )

    results = banner_grabber.grab_banners(
        target="localhost",
        ports=[8080, 22, 443, 80],
        timeout=0.1,
        threads=4,
    )

    assert [
        result["port"]
        for result in results
    ] == [22, 80, 443, 8080]


def test_passive_banner_from_local_tcp_server():
    ready = threading.Event()

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    server.bind(
        ("127.0.0.1", 0)
    )

    server.listen(1)

    port = server.getsockname()[1]

    def serve():
        ready.set()

        connection, _ = server.accept()

        with connection:
            connection.sendall(
                b"SSH-2.0-MurayamaLab\r\n"
            )

        server.close()

    thread = threading.Thread(
        target=serve,
        daemon=True,
    )

    thread.start()

    assert ready.wait(timeout=1)

    result = banner_grabber.grab_banner(
        target="127.0.0.1",
        port=port,
        timeout=1.0,
    )

    thread.join(timeout=1)

    assert result is not None
    assert result["port"] == port
    assert result["protocol"] == "tcp"
    assert result["banner"] == "SSH-2.0-MurayamaLab"


def test_http_active_probe_with_local_server(
    monkeypatch,
):
    ready = threading.Event()
    request_received = []

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    server.bind(
        ("127.0.0.1", 0)
    )

    server.listen(1)

    port = server.getsockname()[1]

    monkeypatch.setattr(
        banner_grabber,
        "HTTP_PORTS",
        {port},
    )

    def serve():
        ready.set()

        connection, _ = server.accept()

        with connection:
            data = connection.recv(4096)

            request_received.append(
                data.decode(
                    "utf-8",
                    errors="replace",
                )
            )

            connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Server: MurayamaTest\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )

        server.close()

    thread = threading.Thread(
        target=serve,
        daemon=True,
    )

    thread.start()

    assert ready.wait(timeout=1)

    result = banner_grabber.grab_banner(
        target="127.0.0.1",
        port=port,
        timeout=1.0,
    )

    thread.join(timeout=1)

    assert request_received
    assert (
        "HEAD / HTTP/1.1"
        in request_received[0]
    )
    assert result is not None
    assert result["port"] == port
    assert result["protocol"] == "tcp"
    assert "HTTP/1.1 200 OK" in result["banner"]
    assert "Server: MurayamaTest" in result["banner"]