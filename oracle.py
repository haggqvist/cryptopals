from dataclasses import dataclass, field
from random import SystemRandom
from typing import Protocol

from aes import CBC, ECB, might_be_ecb


random = SystemRandom()


def random_key(size: int = 16) -> bytes:
    return random.randbytes(size)


def random_bytes(max_len: int = 32) -> bytes:
    return random.randbytes(random.randint(0, max_len))


class EncryptionOracle(Protocol):
    def encrypt(self, plaintext: bytes) -> bytes: ...


@dataclass
class RandomOracle:
    """
    Randomly selects ECB or CBC and pads input plaintext
    with 5-10 bytes on both ends.
    """

    display: bool = False
    key: bytes = field(default_factory=random_key)
    last_mode: str | None = None

    def encrypt(self, plaintext: bytes) -> bytes:
        padding = random.randbytes(random.randrange(5, 11))
        padded_plaintext = padding + plaintext + padding

        if random.randint(0, 1):
            if self.display:
                print("chosen mode: ECB")
            self.last_mode = "ECB"
            return ECB(key=self.key).encrypt(plaintext=padded_plaintext)
        else:
            if self.display:
                print("chosen mode: CBC")
            self.last_mode = "CBC"
            return CBC(key=self.key, iv=random.randbytes(len(self.key))).encrypt(
                plaintext=padded_plaintext
            )


@dataclass
class WeirdPaddingOracle:
    padding: bytes
    key: bytes = field(default_factory=random_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        return ECB(key=self.key).encrypt(plaintext=plaintext + self.padding)


@dataclass
class RandomPrefixPaddingOracle(WeirdPaddingOracle):
    prefix: bytes = field(default_factory=random_bytes)

    def encrypt(self, plaintext: bytes) -> bytes:
        return ECB(key=self.key).encrypt(
            plaintext=self.prefix + plaintext + self.padding
        )


def detect_ecb_or_cbc(encryption_oracle: EncryptionOracle, repeat: int = 4) -> str:
    plaintext = b"YELLOW SUBMARINE"
    out = encryption_oracle.encrypt(plaintext * repeat)
    if might_be_ecb(out):
        return "ECB"
    else:
        return "CBC"
