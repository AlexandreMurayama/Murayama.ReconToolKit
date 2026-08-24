COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    8080,
    8443,
]

def get_ports_to_scan(args) -> list[int]:
    if args.port is not None:
        if not 1 <= args.port <= 65535:
            raise ValueError(
                "Port must be between 1 and 65535"
            )

        return [args.port]

    if args.port_range:
        try:
            start_text, end_text = args.port_range.split("-", maxsplit=1)

            start = int(start_text)
            end = int(end_text)

        except ValueError as error:
            raise ValueError(
                "Port range must use the format START-END"
            ) from error

        if not 1 <= start <= 65535:
            raise ValueError(
                "Start port must be between 1 and 65535"
            )

        if not 1 <= end <= 65535:
            raise ValueError(
                "End port must be between 1 and 65535"
            )

        if start > end:
            raise ValueError(
                "Start port cannot be greater than end port"
            )

        return list(range(start, end + 1))

    return COMMON_PORTS

def validate_tcp_port(
    port: int,
    option_name: str = "port",
) -> int:
    if not 1 <= port <= 65535:
        raise ValueError(
            f"{option_name} must be between 1 and 65535"
        )

    return port