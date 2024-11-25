import base64
from itertools import batched

from util import find_keysize, transpose
from xor import crack_1_byte, repeating_key

with open("./data/6.txt") as f:
    data = base64.b64decode(f.read())

key_sizes = find_keysize(data)
best_key_size, *_ = key_sizes

print(f"Key Size:\t{best_key_size}")

blocks = [bytes(block) for block in batched(data, best_key_size)]
transposed_blocks = transpose(blocks)

key = b""
for block in transposed_blocks:
    a = crack_1_byte(block)
    key += a.key

print(f"Key:\t\t{key.decode()}")

decrypted_text = bytes(repeating_key(data, key))
print("Text:")
print(decrypted_text.decode())
