import string
from typing import Sequence

ASCII_CHARS = [ord(" ")] + [ord(c) for c in string.ascii_lowercase]


def character_frequency(bytez: bytes, chars: Sequence[int] = ASCII_CHARS) -> float:
    char_count = sum(x in chars for x in bytez)
    return char_count / len(bytez)


def is_text(
    bytez: bytes, threshold: float = 0.75, chars: Sequence[int] = ASCII_CHARS
) -> bool:
    return character_frequency(bytez=bytez, chars=chars) > threshold
