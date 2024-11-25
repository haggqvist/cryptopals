from dataclasses import dataclass, field
from urllib.parse import quote_plus

from aes import CBC
from util import pkcs7_unpad, random_key
from xor import xor


def generate_user_string(user_data: str) -> str:
    return (
        "comment1=cooking%20MCs;userdata="
        + quote_plus(user_data)
        + ";comment2=%20like%20a%20pound%20of%20bacon"
    )


@dataclass
class CBCUserStringOracle:
    key: bytes = field(default_factory=random_key)
    iv: bytes = field(default_factory=random_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        user_string = generate_user_string(user_data=plaintext.decode())
        return CBC(key=self.key, iv=self.iv).encrypt(plaintext=user_string.encode())

    def decrypt(self, ciphertext: bytes) -> bytes:
        return CBC(key=self.key, iv=self.iv).decrypt(ciphertext=ciphertext)

    def decrypt_and_verify(self, ciphertext: bytes, verbose: bool = False) -> bool:
        plaintext = pkcs7_unpad(self.decrypt(ciphertext=ciphertext))
        if verbose:
            print(plaintext)
        return b";admin=true;" in plaintext


if __name__ == "__main__":
    block_size = 16
    oracle = CBCUserStringOracle()

    # input starts on a clean block since
    # len("comment1=cooking%20MCs;userdata=") == 32

    # create 2 attacker-controlled blocks with fill bytes
    fill = b"a"
    payload = bytes(fill * block_size * 2)
    ciphertext = oracle.encrypt(payload)

    target = b";admin=true"

    # create a block that when xor'd against fill block produces the target msg
    flip_block = bytes(
        xor(fill * block_size, (block_size - len(target)) * fill + target)
    )
    assert bytes(xor(flip_block, payload[:block_size])) == b"aaaaa;admin=true"

    # xor against block 3 in ciphertext
    crafted_block = bytes(
        xor(ciphertext[2 * block_size : (2 + 1) * block_size], flip_block)
    )
    # inject block in ct
    crafted_ct = (
        ciphertext[: 2 * block_size] + crafted_block + ciphertext[3 * block_size :]
    )

    assert oracle.decrypt_and_verify(crafted_ct, verbose=True)

    # this attack works because there is no authentication/integrity of the message
