from collections.abc import Iterable
from dataclasses import dataclass
from itertools import cycle

from words import character_frequency


def xor(a: bytes, b: bytes) -> Iterable[int]:
    for x, y in zip(a, b):
        yield x ^ y


def repeating_key(text: bytes, key: bytes | int) -> bytes:
    if isinstance(key, int):
        key = int.to_bytes(key)
    return bytes(x ^ y for x, y in zip(text, cycle(key)))


@dataclass
class XORGuess:
    frequency: float
    key: bytes
    output: bytes


def crack_1_byte(cipher: bytes) -> XORGuess:
    """
    Crack 1-byte repeating XOR
    """
    best_guess = XORGuess(frequency=0, key=b"", output=b"")
    for i in range(256):
        output = bytes(repeating_key(cipher, i))
        frequency = character_frequency(output)
        current_guess = XORGuess(
            frequency=frequency,
            key=i.to_bytes(),
            output=output,
        )
        if frequency > best_guess.frequency:
            best_guess = current_guess

    return best_guess
