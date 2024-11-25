import base64

from aes import ECB, CBC
from util import pkcs7_unpad


key = b"YELLOW SUBMARINE"
plain = "moo"

ecb = ECB(key=key)
encrypted = ecb.encrypt(plaintext=plain.encode())
decrypted = ecb.decrypt(ciphertext=encrypted)
decrypted = pkcs7_unpad(decrypted)

assert decrypted.decode() == plain

cbc = CBC(key=key, iv=bytes(16))
encrypted = cbc.encrypt(plaintext=plain.encode())
decrypted = cbc.decrypt(ciphertext=encrypted)
decrypted = pkcs7_unpad(decrypted)

assert decrypted.decode() == plain

with open("./data/10.txt") as f:
    ciphertext = base64.b64decode(f.read())

cbc_2 = CBC(key=key, iv=bytes(16))
plaintext = cbc_2.decrypt(ciphertext=ciphertext)
plaintext = pkcs7_unpad(plaintext)
print(plaintext.decode())
