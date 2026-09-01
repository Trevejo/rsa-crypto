#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Framing mínimo para transportar mensagens JSON sobre TCP.

TCP não preserva fronteiras de mensagens. Cada pacote da atividade termina
com uma quebra de linha, e estas funções garantem que um JSON completo seja
enviado com ``sendall`` e lido com ``readline``.
"""

import json
from socket import socket
from typing import Any, BinaryIO, Dict


MAX_FRAME_BYTES = 16384


def send_json(connection: socket, payload: Dict[str, Any]) -> None:
    """Serializa um dicionário como uma linha JSON e envia tudo."""

    frame = (
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(frame) > MAX_FRAME_BYTES:
        raise ValueError("O pacote JSON excede o limite definido")
    connection.sendall(frame)


def receive_json(reader: BinaryIO) -> Dict[str, Any]:
    """Lê uma linha JSON completa do fluxo TCP."""

    line = reader.readline(MAX_FRAME_BYTES + 1)
    if not line:
        raise ConnectionError("A outra ponta encerrou a conexão")
    if len(line) > MAX_FRAME_BYTES or not line.endswith(b"\n"):
        raise ValueError("Pacote JSON ausente, incompleto ou grande demais")

    try:
        payload = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Pacote JSON inválido") from exc
    if not isinstance(payload, dict):
        raise ValueError("O pacote JSON precisa ser um objeto")
    return payload
