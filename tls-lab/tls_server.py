import socket
import ssl


HOST = "127.0.0.1"
PORT = 9443

context = ssl.SSLContext(
    ssl.PROTOCOL_TLS_SERVER
)

context.load_cert_chain(
    certfile="cert.pem",
    keyfile="key.pem",
)

with socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM,
) as server:
    server.bind(
        (HOST, PORT)
    )

    server.listen(5)

    print(
        f"TLS lab listening on "
        f"https://localhost:{PORT}"
    )

    while True:
        client, address = server.accept()

        try:
            with context.wrap_socket(
                    client,
                    server_side=True,
            ) as tls_client:
                print(
                    f"TLS connection from "
                    f"{address[0]}:{address[1]}"
                )

        except ssl.SSLError as error:
            print(
                f"TLS handshake failed: {error}"
            )

            client.close()