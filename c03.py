from xor import crack_1_byte

s = bytes.fromhex(
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
)

result = crack_1_byte(s)

print(f"Key:\t{result.key.decode()}")
print(f"Text:\t{result.output.decode()}")
