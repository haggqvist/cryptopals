from util import pkcs7_unpad

assert pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04") == b"ICE ICE BABY"

try:
    pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05")
except ValueError:
    ...

try:
    pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04")
except ValueError:
    ...
