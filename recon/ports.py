import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


KNOWN_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    8080: "http-alt",
    8443: "https-alt",
}


def scan_port(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> dict | None:
    service = KNOWN_SERVICES.get(port)

    if service is None:
        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = "unknown"

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        ) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((target, port))

            if result != 0:
                return None

            return {
                "port": port,
                "service": service,
            }

    except socket.gaierror:
        return None


def scan_ports(
    target: str,
    ports: list[int],
    threads: int = 50,
    timeout: float = 1.0,
) -> list[dict]:
    try:
        socket.gethostbyname(target)
    except socket.gaierror as error:
        raise ValueError(
            f"Unable to resolve target: {target}"
        ) from error

    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(
                scan_port,
                target,
                port,
                timeout,
            )
            for port in ports
        ]

        for future in as_completed(futures):
            result = future.result()

            if result is not None:
                results.append(result)

    results.sort(key=lambda item: item["port"])

    return results