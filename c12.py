import base64
import string

from oracle import detect_ecb_or_cbc, WeirdPaddingOracle, EncryptionOracle
from util import detect_block_size


unknown_string = (
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)


def find_padding_length(oracle: EncryptionOracle, block_size: int) -> int:
    initial_length = len(oracle.encrypt(b""))
    for i in range(1, block_size):
        length = len(oracle.encrypt(bytes(i)))
        if length > initial_length:
            break
    return length - block_size - i + 1


def brute_force_single_byte(
    pad: bytes,
    target_block: bytes,
    oracle: EncryptionOracle,
    bytes_to_try: bytes | None = None,
    offset: int = 0,
) -> bytes:
    block_size = len(target_block)

    if bytes_to_try is None:
        bytes_to_try = bytes(range(2**8))

    for byte in bytes_to_try:
        result = oracle.encrypt(plaintext=pad + bytes([byte]))
        if result[offset * block_size : (1 + offset) * block_size] == target_block:
            return bytes([byte])
    else:
        return b""


if __name__ == "__main__":
    padding_oracle = WeirdPaddingOracle(padding=base64.b64decode(unknown_string))

    block_size = detect_block_size(padding_oracle.encrypt)
    assert detect_ecb_or_cbc(padding_oracle) == "ECB"

    expected_message_length = find_padding_length(
        oracle=padding_oracle, block_size=block_size
    )
    print(f"Expected msg length: {expected_message_length}")

    total_blocks = (expected_message_length // block_size) + 1

    # create a set of reference ciphertexts with padding block_size-1..0
    # this only needs to be done once, to have each block at an offset of 1..15 bytes.
    ciphertexts = [
        padding_oracle.encrypt(plaintext=bytes(n)) for n in reversed(range(block_size))
    ]

    plaintext = b""
    for i in range(total_blocks):
        for n in range(block_size):
            # create padding of "\x00" * (block_size - 1) || plaintext
            # select trailing [block_size - 1] bytes
            pad = (bytes(block_size - 1) + plaintext)[-(block_size - 1) :]
            target = ciphertexts[n][i * block_size : i * block_size + block_size]
            plaintext += brute_force_single_byte(
                pad=pad,
                target_block=target,
                oracle=padding_oracle,
                bytes_to_try=string.printable.encode(),
            )

    print(plaintext.decode())
