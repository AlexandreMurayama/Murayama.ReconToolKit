import subprocess
import xml.etree.ElementTree as ET


def run_nmap(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 30.0,
) -> list[dict]:
    command = [
        "nmap",
        "-sV",
        "-oX",
        "-",
        target,
    ]

    if ports:
        port_list = ",".join(str(port) for port in ports)

        command[1:1] = [
            "-p",
            port_list,
        ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    except subprocess.TimeoutExpired as error:
        raise ValueError(
            f"Nmap scan timed out after {timeout} seconds"
        ) from error

    except FileNotFoundError as error:
        raise ValueError(
            "Nmap executable was not found in PATH"
        ) from error

    if result.returncode != 0:
        raise ValueError(
            f"Nmap failed: {result.stderr.strip()}"
        )

    return _parse_nmap_xml(result.stdout)


def _parse_nmap_xml(xml_data: str) -> list[dict]:
    root = ET.fromstring(xml_data)

    results = []

    for port_element in root.findall(".//port"):
        state_element = port_element.find("state")

        if state_element is None:
            continue

        if state_element.get("state") != "open":
            continue

        service_element = port_element.find("service")

        result = {
            "port": int(port_element.get("portid")),
            "protocol": port_element.get("protocol"),
            "service": "unknown",
            "product": None,
            "version": None,
        }

        if service_element is not None:
            result["service"] = service_element.get(
                "name",
                "unknown",
            )

            result["product"] = service_element.get(
                "product"
            )

            result["version"] = service_element.get(
                "version"
            )

        results.append(result)

    results.sort(
        key=lambda item: item["port"]
    )

    return results