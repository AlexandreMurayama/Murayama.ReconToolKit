import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed


HTTP_PORTS = {80, 8080}
HTTPS_PORTS = {443, 8443}
SMTP_PORTS = {25, 587}


def _decode_banner(data: bytes) -> str | None:
    if not data:
        return None

    banner = data.decode(
        "utf-8",
        errors="replace",
    ).strip()

    return banner or None


def _build_http_probe(target: str) -> bytes:
    return (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"User-Agent: MurayamaRecon/0.1.0\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()


def _receive_banner(
    sock: socket.socket,
    size: int = 4096,
) -> str | None:
    try:
        data = sock.recv(size)
    except socket.timeout:
        return None

    return _decode_banner(data)


def _grab_https_banner(
    target: str,
    port: int,
    timeout: float,
) -> str | None:
    context = ssl.create_default_context()

    # Reconnaissance must also be able to inspect services
    # using self-signed or otherwise untrusted certificates.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection(
        (target, port),
        timeout=timeout,
    ) as raw_socket:
        with context.wrap_socket(
            raw_socket,
            server_hostname=target,
        ) as tls_socket:
            tls_socket.settimeout(timeout)

            tls_socket.sendall(
                _build_http_probe(target)
            )

            return _receive_banner(
                tls_socket
            )


def _grab_tcp_banner(
    target: str,
    port: int,
    timeout: float,
) -> str | None:
    with socket.create_connection(
        (target, port),
        timeout=timeout,
    ) as sock:
        sock.settimeout(timeout)

        if port in HTTP_PORTS:
            sock.sendall(
                _build_http_probe(target)
            )

            return _receive_banner(sock)

        # SSH, FTP and some other protocols normally
        # identify themselves immediately after connection.
        passive_banner = _receive_banner(sock)

        if passive_banner:
            return passive_banner

        if port in SMTP_PORTS:
            sock.sendall(
                b"EHLO murayama-recon.local\r\n"
            )

            return _receive_banner(sock)

        return None


def grab_banner(
    target: str,
    port: int,
    timeout: float = 2.0,
) -> dict | None:
    try:
        if port in HTTPS_PORTS:
            banner = _grab_https_banner(
                target=target,
                port=port,
                timeout=timeout,
            )

            protocol = "https"

        else:
            banner = _grab_tcp_banner(
                target=target,
                port=port,
                timeout=timeout,
            )

            protocol = "tcp"

        if banner is None:
            return None

        return {
            "port": port,
            "protocol": protocol,
            "banner": banner,
        }

    except (
        socket.timeout,
        socket.gaierror,
        ConnectionRefusedError,
        ssl.SSLError,
        OSError,
    ):
        return None


def grab_banners(
    target: str,
    ports: list[int],
    timeout: float = 2.0,
    threads: int = 10,
) -> list[dict]:
    results = []

    with ThreadPoolExecutor(
        max_workers=threads
    ) as executor:
        futures = {
            executor.submit(
                grab_banner,
                target,
                port,
                timeout,
            ): port
            for port in ports
        }

        for future in as_completed(futures):
            result = future.result()

            if result is not None:
                results.append(result)

    results.sort(
        key=lambda item: item["port"]
    )

    return results