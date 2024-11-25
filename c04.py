from words import is_text
from xor import crack_1_byte

with open("./data/4.txt") as f:
    samples = f.read().splitlines()

for n, sample in enumerate(samples):
    result = crack_1_byte(bytes.fromhex(sample))
    if is_text(result.output):
        print(f"Line:\t{n}")
        print(f"Key:\t{result.key.decode()}")
        print(f"Text:\t{result.output.decode()}")
