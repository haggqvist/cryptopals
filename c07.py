import base64

from aes import ECB

with open("./data/7.txt") as f:
    ciphertext = base64.b64decode(f.read())

ecb = ECB(key=b"YELLOW SUBMARINE")
print(ecb.decrypt(ciphertext=ciphertext).decode())
