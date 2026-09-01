#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rotinas didáticas para gerar e utilizar chaves RSA de 4096 bits.

O teste de primalidade é baseado no algoritmo Miller-Rabin fornecido no
arquivo ``primo_hyper.py``. A geração dos candidatos segue a ideia do
``gen_4096.py``: o bit mais significativo é ligado para preservar o tamanho
do número e o bit menos significativo é ligado para gerar apenas candidatos
ímpares.

Para uma aplicação real, prefira uma biblioteca criptográfica auditada. Este
módulo existe para tornar visíveis as etapas matemáticas solicitadas na
atividade.
"""

import base64
import binascii
import math
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Tuple


RSA_BITS = 4096
PRIME_BITS = RSA_BITS // 2
PUBLIC_EXPONENT = 65537
MILLER_RABIN_ROUNDS = 12
RSA_PADDING_NAME = "RSAES-PKCS1-v1_5"


@dataclass(frozen=True)
class PublicKey:
    """Parte pública da chave RSA: ``(n, e)``."""

    n: int
    e: int


@dataclass(frozen=True)
class PrivateKey:
    """Parte privada necessária para decifrar: ``(n, d)``."""

    n: int
    d: int


def is_probable_prime(n: int, rounds: int = MILLER_RABIN_ROUNDS) -> bool:
    """Retorna se ``n`` provavelmente é primo usando Miller-Rabin.

    Para valores menores que 2**64 são usadas as mesmas bases determinísticas
    do PrimoHyper. Para valores maiores, como os candidatos de 2048 bits,
    são escolhidas bases aleatórias de forma criptograficamente segura.
    """

    if n < 2:
        return False

    # Pré-checagem barata para eliminar rapidamente compostos pequenos.
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small_primes:
        return True
    for prime in small_primes:
        if n % prime == 0:
            return False

    # Escreve n - 1 como d * 2**s, com d ímpar.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    def passes_round(base: int) -> bool:
        value = pow(base, d, n)
        if value == 1 or value == n - 1:
            return True
        for _ in range(s - 1):
            value = (value * value) % n
            if value == n - 1:
                return True
        return False

    if n < (1 << 64):
        bases: Iterable[int] = (
            2,
            325,
            9375,
            28178,
            450775,
            9780504,
            1795265022,
        )
    else:
        if rounds < 1:
            raise ValueError("A quantidade de rodadas deve ser positiva")
        bases = (secrets.randbelow(n - 3) + 2 for _ in range(rounds))

    for base in bases:
        base %= n
        if base == 0:
            continue
        if not passes_round(base):
            return False
    return True


def random_odd_candidate(bits: int) -> int:
    """Gera um candidato ímpar com exatamente ``bits`` bits.

    Esta é a versão reutilizável da estratégia do ``gen_4096.py``. O módulo
    usa ``secrets`` no lugar de ``random`` porque os valores participam da
    geração de chaves criptográficas.
    """

    if bits < 2:
        raise ValueError("O candidato precisa ter pelo menos 2 bits")

    candidate = secrets.randbits(bits)
    candidate |= 1 << (bits - 1)
    candidate |= 1
    return candidate


def generate_prime(bits: int = PRIME_BITS) -> int:
    """Gera um primo provável com ``bits`` bits."""

    while True:
        candidate = random_odd_candidate(bits)
        if is_probable_prime(candidate):
            return candidate


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Calcula ``gcd(a, b)`` e os coeficientes de Bézout."""

    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = _extended_gcd(b, a % b)
    return gcd, y1, x1 - (a // b) * y1


def modular_inverse(value: int, modulus: int) -> int:
    """Retorna o inverso modular de ``value`` módulo ``modulus``."""

    gcd, coefficient, _ = _extended_gcd(value, modulus)
    if gcd != 1:
        raise ValueError("Não existe inverso modular para os valores informados")
    return coefficient % modulus


def generate_key_pair(bits: int = RSA_BITS) -> Tuple[PublicKey, PrivateKey]:
    """Gera um par RSA cujo módulo possui exatamente ``bits`` bits.

    Com ``bits=4096``, cada fator primo possui 2048 bits. Gerar dois primos
    de 4096 bits produziria um módulo de aproximadamente 8192 bits, por isso
    o tamanho dos fatores é metade do tamanho desejado para a chave RSA.
    """

    if bits < 1024 or bits % 2 != 0:
        raise ValueError("O tamanho RSA deve ser par e ter pelo menos 1024 bits")

    prime_bits = bits // 2
    while True:
        p = generate_prime(prime_bits)
        q = generate_prime(prime_bits)
        if p == q:
            continue

        n = p * q
        # Os fatores têm 2048 bits, mas o produto pode ocasionalmente ter
        # 4095 bits. Nesse caso, gere outro par para satisfazer a atividade.
        if n.bit_length() != bits:
            continue

        phi = (p - 1) * (q - 1)
        if math.gcd(PUBLIC_EXPONENT, phi) != 1:
            continue

        d = modular_inverse(PUBLIC_EXPONENT, phi)
        return PublicKey(n=n, e=PUBLIC_EXPONENT), PrivateKey(n=n, d=d)


def _modulus_bytes(modulus: int) -> int:
    """Calcula o tamanho do módulo em bytes."""

    return (modulus.bit_length() + 7) // 8


def rsa_encrypt(message: bytes, public_key: PublicKey) -> bytes:
    """Cifra bytes com RSA e preenchimento PKCS#1 v1.5.

    O preenchimento inclui bytes aleatórios, portanto duas cifragens da mesma
    mensagem normalmente produzem cifrados diferentes. Um módulo de 4096
    bits comporta até ``k - 11`` bytes neste esquema.
    """

    if not isinstance(message, bytes):
        raise TypeError("A mensagem precisa ser bytes")

    block_size = _modulus_bytes(public_key.n)
    max_message_size = block_size - 11
    if len(message) > max_message_size:
        raise ValueError(
            f"Mensagem muito longa: no máximo {max_message_size} bytes "
            f"para este módulo"
        )

    padding_size = block_size - len(message) - 3
    padding = bytearray()
    while len(padding) < padding_size:
        random_bytes = secrets.token_bytes(padding_size - len(padding))
        padding.extend(byte for byte in random_bytes if byte != 0)

    encoded_message = b"\x00\x02" + bytes(padding[:padding_size]) + b"\x00" + message
    message_number = int.from_bytes(encoded_message, byteorder="big")
    encrypted_number = pow(message_number, public_key.e, public_key.n)
    return encrypted_number.to_bytes(block_size, byteorder="big")


def rsa_decrypt(ciphertext: bytes, private_key: PrivateKey) -> bytes:
    """Decifra e valida um bloco RSA com PKCS#1 v1.5."""

    if not isinstance(ciphertext, bytes):
        raise TypeError("O texto cifrado precisa ser bytes")

    block_size = _modulus_bytes(private_key.n)
    if len(ciphertext) != block_size:
        raise ValueError("O texto cifrado possui tamanho incompatível com a chave")

    ciphertext_number = int.from_bytes(ciphertext, byteorder="big")
    if ciphertext_number >= private_key.n:
        raise ValueError("O texto cifrado não pertence ao módulo RSA")

    encoded_number = pow(ciphertext_number, private_key.d, private_key.n)
    encoded_message = encoded_number.to_bytes(block_size, byteorder="big")

    if not encoded_message.startswith(b"\x00\x02"):
        raise ValueError("Preenchimento RSA inválido")

    separator = encoded_message.find(b"\x00", 2)
    if separator < 0:
        raise ValueError("Separador do preenchimento RSA não encontrado")

    padding = encoded_message[2:separator]
    if len(padding) < 8 or any(byte == 0 for byte in padding):
        raise ValueError("Preenchimento RSA inválido")
    return encoded_message[separator + 1 :]


def public_key_to_payload(public_key: PublicKey, role: str) -> Dict[str, Any]:
    """Converte a chave pública para o JSON enviado em texto puro."""

    return {
        "type": "public_key",
        "role": role,
        "algorithm": "RSA-4096",
        "bits": public_key.n.bit_length(),
        "n": str(public_key.n),
        "e": str(public_key.e),
    }


def public_key_from_payload(payload: Dict[str, Any]) -> PublicKey:
    """Valida e reconstrói uma chave pública recebida pelo TCP."""

    if payload.get("type") != "public_key":
        raise ValueError("Era esperada uma mensagem de chave pública")
    if payload.get("algorithm") != "RSA-4096":
        raise ValueError("Algoritmo ou tamanho de chave inesperado")

    try:
        modulus = int(payload["n"])
        exponent = int(payload["e"])
        declared_bits = int(payload["bits"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Campos inválidos na chave pública") from exc

    if modulus <= 0 or modulus.bit_length() != RSA_BITS or declared_bits != RSA_BITS:
        raise ValueError("A chave pública recebida não possui 4096 bits")
    if exponent != PUBLIC_EXPONENT:
        raise ValueError("Expoente público inesperado")
    return PublicKey(n=modulus, e=exponent)


def encrypted_payload(ciphertext: bytes, message_type: str) -> Dict[str, Any]:
    """Monta um pacote JSON para transportar o texto cifrado em Base64."""

    return {
        "type": message_type,
        "algorithm": RSA_PADDING_NAME,
        "encoding": "base64",
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def ciphertext_from_payload(payload: Dict[str, Any], expected_type: str) -> bytes:
    """Extrai e valida o texto cifrado em Base64 de um pacote JSON."""

    if payload.get("type") != expected_type:
        raise ValueError(f"Era esperada uma mensagem do tipo {expected_type}")
    if payload.get("algorithm") != RSA_PADDING_NAME:
        raise ValueError("Esquema RSA inesperado")
    if payload.get("encoding") != "base64":
        raise ValueError("Codificação do texto cifrado inesperada")

    try:
        encoded_ciphertext = payload["ciphertext"]
        if not isinstance(encoded_ciphertext, str):
            raise TypeError
        return base64.b64decode(encoded_ciphertext.encode("ascii"), validate=True)
    except (
        KeyError,
        TypeError,
        UnicodeEncodeError,
        ValueError,
        binascii.Error,
    ) as exc:
        raise ValueError("Texto cifrado Base64 inválido") from exc
