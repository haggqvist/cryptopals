from aes import might_be_ecb

with open("./data/8.txt") as f:
    ciphertexts = f.read().splitlines()

for n, ciphertext in enumerate(ciphertexts):
    duplicates = might_be_ecb(bytes.fromhex(ciphertext))
    if duplicates:
        print(f"{n} might be AES ECB")
        print("Duplicate block(s):")
        for duplicate in duplicates:
            print(bytes(duplicate).hex())
