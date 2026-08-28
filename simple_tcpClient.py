#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Alice: cliente TCP que usa RSA para proteger a mensagem."""

import argparse
import sys
import time
from socket import AF_INET, SOCK_STREAM, socket

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


DEFAULT_SERVER = "192.168.78.169"
DEFAULT_PORT = 1300
DEFAULT_MESSAGE = (
    "The information security is of significant importance to ensure the "
    "privacy of communications"
)


def parse_args() -> argparse.Namespace:
    """Le o endereco do Bob e permite substituir a mensagem padrao."""

    parser = argparse.ArgumentParser(
        description="Cliente Alice: troca de chaves e mensagem RSA-4096"
    )
    parser.add_argument(
        "server",
        nargs="?",
        default=DEFAULT_SERVER,
        help=f"IP ou hostname do Bob (padrao: {DEFAULT_SERVER})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"porta TCP do Bob (padrao: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--message",
        default=DEFAULT_MESSAGE,
        help="mensagem UTF-8; por padrao usa a mensagem da atividade",
    )
    return parser.parse_args()


def main() -> None:
    # O cronometro comeca antes da geracao das chaves, como solicitado na
    # atividade, e termina logo depois da apresentacao da resposta maiuscula.
    start_time = time.perf_counter()
    args = parse_args()
    message = args.message.encode("utf-8")

    print("[Alice] Gerando o par de chaves RSA-4096...")
    public_key, private_key = generate_key_pair()
    print("[Alice] Chave pronta. Conectando ao Bob...")

    with socket(AF_INET, SOCK_STREAM) as client_socket:
        client_socket.connect((args.server, args.port))
        with client_socket.makefile("rb") as reader:
            # A chave publica de Alice viaja sem cifragem, conforme a etapa 4.
            send_json(client_socket, public_key_to_payload(public_key, "Alice"))
            bob_payload = receive_json(reader)
            bob_public_key = public_key_from_payload(bob_payload)
            print(
                f"[Alice] Chave publica de Bob recebida "
                f"({bob_public_key.n.bit_length()} bits)."
            )

            encrypted_message = rsa_encrypt(message, bob_public_key)
            send_json(
                client_socket,
                encrypted_payload(encrypted_message, "encrypted_message"),
            )
            print("[Alice] Mensagem cifrada enviada ao Bob.")

            response_payload = receive_json(reader)
            encrypted_response = ciphertext_from_payload(
                response_payload, "encrypted_response"
            )
            uppercase_message = rsa_decrypt(encrypted_response, private_key)
            uppercase_text = uppercase_message.decode("utf-8")

            print(f"[Alice] Mensagem maiuscula recebida: {uppercase_text}", flush=True)
            end_time = time.perf_counter()

    elapsed_ms = (end_time - start_time) * 1000.0
    print(
        f"[Alice] RTT total (inicio do programa ate a apresentacao): "
        f"{elapsed_ms:.3f} ms"
    )


if __name__ == "__main__":
    try:
        main()
    except (ConnectionError, OSError, UnicodeError, ValueError) as error:
        print(f"[Alice][ERRO] {error}", file=sys.stderr)
        raise SystemExit(1)
