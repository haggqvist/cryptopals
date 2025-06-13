import contextlib

from util import pkcs7_unpad

assert pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04") == b"ICE ICE BABY"

with contextlib.suppress(ValueError):
    pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05")

with contextlib.suppress(ValueError):
    pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04")
