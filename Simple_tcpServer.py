#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bob: servidor TCP que recebe, decifra e devolve a mensagem em maiúsculas."""

import argparse
import sys
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, socket

from rsa_4096 import (
    ciphertext_from_payload,
    encrypted_payload,
    generate_key_pair,
    public_key_from_payload,
    public_key_to_payload,
    rsa_decrypt,
    rsa_encrypt,
)
from tcp_protocol import receive_json, send_json


DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 1300


def parse_args() -> argparse.Namespace:
    """Lê o endereço local e a porta de escuta do Bob."""

    parser = argparse.ArgumentParser(
        description="Servidor Bob: troca de chaves e mensagem RSA-4096"
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"endereço local para escutar (padrão: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"porta TCP de escuta (padrão: {DEFAULT_PORT})",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print("[Bob] Gerando o par de chaves RSA-4096...")
    public_key, private_key = generate_key_pair()
    print("[Bob] Chave pronta.")

    with socket(AF_INET, SOCK_STREAM) as server_socket:
        server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        server_socket.bind((args.host, args.port))
        server_socket.listen(5)
        print(f"[Bob] Aguardando Alice em {args.host}:{args.port}...")

        connection_socket, address = server_socket.accept()
        with connection_socket:
            with connection_socket.makefile("rb") as reader:
                alice_payload = receive_json(reader)
                alice_public_key = public_key_from_payload(alice_payload)
                print(
                    f"[Bob] Chave pública de Alice recebida "
                    f"({alice_public_key.n.bit_length()} bits)."
                )

                # A chave pública de Bob também viaja em texto puro para a
                # próxima etapa poder usar a cifragem RSA.
                send_json(connection_socket, public_key_to_payload(public_key, "Bob"))

                message_payload = receive_json(reader)
                encrypted_message = ciphertext_from_payload(
                    message_payload, "encrypted_message"
                )
                message = rsa_decrypt(encrypted_message, private_key).decode("utf-8")
                print(f"[Bob] Mensagem decifrada de Alice: {message}")

                uppercase_message = message.upper().encode("utf-8")
                encrypted_response = rsa_encrypt(uppercase_message, alice_public_key)
                send_json(
                    connection_socket,
                    encrypted_payload(encrypted_response, "encrypted_response"),
                )
                print("[Bob] Resposta em maiúsculas cifrada e enviada a Alice.")


if __name__ == "__main__":
    try:
        main()
    except (ConnectionError, OSError, UnicodeError, ValueError) as error:
        print(f"[Bob][ERRO] {error}", file=sys.stderr)
        raise SystemExit(1)
