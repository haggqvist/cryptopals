from itertools import batched

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from util import pkcs7_pad
from xor import xor


class AES:
    algorithm: algorithms.AES128 | algorithms.AES256

    def __init__(self, key: bytes, mode: modes.ECB | modes.CBC) -> None:
        if len(key) == 16:
            self.algorithm = algorithms.AES128(key)
        elif len(key) == 32:
            self.algorithm = algorithms.AES256(key)
        else:
            raise ValueError("Key size must be 16 or 32")
        self.cipher = Cipher(algorithm=self.algorithm, mode=mode)


class ECB(AES):
    def __init__(self, key: bytes) -> None:
        super().__init__(key=key, mode=modes.ECB())

    def encrypt(self, plaintext: bytes) -> bytes:
        encryptor = self.cipher.encryptor()
        padded_plaintext = pkcs7_pad(bytez=plaintext)
        return encryptor.update(padded_plaintext) + encryptor.finalize()

    def decrypt(self, ciphertext: bytes) -> bytes:
        decryptor = self.cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


class CBC(AES):
    def __init__(self, key: bytes, iv: bytes) -> None:
        super().__init__(key=key, mode=modes.ECB())
        assert len(iv) == len(key)
        self.iv = iv
        self.block_size = len(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        padded_plaintext = pkcs7_pad(plaintext)
        plaintext_blocks = [
            bytes(block) for block in batched(padded_plaintext, self.block_size)
        ]
        ciphertext = b""
        previous = self.iv
        ecb = ECB(key=self.algorithm.key)
        for block in plaintext_blocks:
            ciphertext_block = ecb.encrypt(bytes(xor(block, previous)))
            ciphertext += ciphertext_block
            previous = ciphertext_block
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        ciphertext_blocks = [
            bytes(block) for block in batched(ciphertext, self.block_size)
        ]
        plaintext = b""
        ecb = ECB(key=self.algorithm.key)
        for n, block in enumerate(ciphertext_blocks):
            previous = self.iv if n == 0 else ciphertext_blocks[n - 1]
            decrypted = ecb.decrypt(block)
            plain = bytes(xor(decrypted, previous))
            plaintext += plain
        return plaintext


def might_be_ecb(ciphertext: bytes, block_size: int = 16) -> set[tuple[int, ...]]:
    duplicates: set[tuple[int, ...]] = set()
    blocks = list(batched(ciphertext, block_size))
    for block in blocks:
        if blocks.count(block) > 1 and block not in duplicates:
            duplicates.add(block)
    return duplicates
