import base64
import string

from oracle import EncryptionOracle, RandomPrefixPaddingOracle
from c12 import unknown_string, find_padding_length, brute_force_single_byte


def find_oracle_prefix_length(oracle: EncryptionOracle, block_size: int) -> int:
    # encrypt 2 different texts with one complete block each
    ciphertext_1 = oracle.encrypt(b"a" * block_size)
    ciphertext_2 = oracle.encrypt(b"b" * block_size)

    # detect first different block
    n = 0
    while n < (len(ciphertext_1) // block_size):
        block_slice = slice(n * block_size, (1 + n) * block_size)
        if ciphertext_1[block_slice] != ciphertext_2[block_slice]:
            break
        n += 1

    # prepend until blocks are identical
    target_block = ciphertext_1[block_slice]
    padding = 1
    while True:
        test_block = prefix_oracle.encrypt(b"a" * padding + b"b" * block_size)[
            block_slice
        ]
        if test_block == target_block:
            break
        padding += 1
    prefix_length = n * block_size + block_size - padding
    return prefix_length


if __name__ == "__main__":
    prefix_oracle = RandomPrefixPaddingOracle(padding=base64.b64decode(unknown_string))
    block_size = 16
    prefix_length = find_oracle_prefix_length(
        oracle=prefix_oracle, block_size=block_size
    )
    expected_message_length = (
        find_padding_length(oracle=prefix_oracle, block_size=block_size) - prefix_length
    )
    print(f"Expected msg length: {expected_message_length}")

    total_blocks = (prefix_length + expected_message_length // block_size) + 1

    # ignore the prefix by adding padding for n blocks and skip over
    ignore_padding = (block_size - prefix_length) % block_size
    num_blocks_to_ignore = (prefix_length + ignore_padding) // block_size

    ciphertexts = [
        prefix_oracle.encrypt(plaintext=bytes(ignore_padding + n))
        for n in reversed(range(block_size))
    ]

    plaintext = b""
    for i in range(num_blocks_to_ignore, total_blocks):
        for n in range(block_size):
            pad = bytes(ignore_padding)
            pad += (bytes(block_size - 1) + plaintext)[-(block_size - 1) :]
            target = ciphertexts[n][i * block_size : i * block_size + block_size]
            plaintext += brute_force_single_byte(
                pad=pad,
                target_block=target,
                oracle=prefix_oracle,
                bytes_to_try=string.printable.encode(),
                offset=num_blocks_to_ignore,
            )
        if len(plaintext) == expected_message_length:
            break

    print(plaintext.decode())
