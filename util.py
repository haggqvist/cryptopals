from collections.abc import Sequence
from itertools import batched, zip_longest
import itertools
from random import SystemRandom
from typing import Callable

from xor import xor

random = SystemRandom()


def edit_distance(a: bytes, b: bytes) -> int:
    bytez = xor(a, b)
    return sum(b.bit_count() for b in bytez)


def normalized_edit_distance(cipher: bytes, key_size: int) -> float:
    chunks = [bytes(chunk) for chunk in batched(cipher, key_size)]
    chunk_1, chunk_2 = chunks[:2]
    distances = [
        edit_distance(c, chunk) for chunk in chunks[2:] for c in (chunk_1, chunk_2)
    ]
    return (sum(distances) / len(distances)) / key_size


def find_keysize(
    cipher: bytes, min_keysize: int = 2, max_keysize: int = 40
) -> dict[int, float]:
    edit_distance_by_key_size: dict[int, float] = {}
    for key_size in range(min_keysize, max_keysize + 1):
        normalized_distance = normalized_edit_distance(cipher, key_size)
        edit_distance_by_key_size[key_size] = normalized_distance
    return dict(sorted(edit_distance_by_key_size.items(), key=lambda item: item[1]))


def transpose(blocks: Sequence[bytes]) -> list[bytes]:
    transposed = zip_longest(*blocks)
    filtered = [bytes(filter(lambda x: x is not None, i)) for i in transposed]
    return filtered


def pkcs7_pad(bytez: bytes, block_size: int = 16) -> bytes:
    extra = -len(bytez) % block_size
    return bytez + bytes([extra] * extra)


def pkcs7_unpad(bytez: bytes, verify: bool = True) -> bytes:
    extra = bytez[-1]
    if verify:
        if not bytes([extra] * extra) == bytez[-extra:]:
            raise ValueError("Invalid PKCS#7 padding")
    return bytez[:-extra:]


def random_key(size: int = 16) -> bytes:
    return random.randbytes(size)


def detect_block_size(encryption_function: Callable[[bytes], bytes]) -> int:
    bytez = b""
    initial_length = current_length = len(encryption_function(bytez))
    while current_length == initial_length:
        bytez += b"A"
        current_length = len(encryption_function(bytez))
    return current_length - initial_length


def pretty_print_bytes(bytez: bytes, chunk_size: int, decode: bool = False):
    chunks = itertools.batched(bytez, n=chunk_size)
    print("|" + "|".join(f"{n:<2}" for n in range(chunk_size)) + "|")
    print("---" * chunk_size + "-")
    for chunk in chunks:
        print("|", end="")
        for b in chunk:
            if decode:
                if b < 0x20:
                    print(f"{b:02x}|", end="")
                else:
                    print(f"{chr(b):<2}|", end="")
            else:
                print(f"{b:02x}|", end="")
        print()
    print()
