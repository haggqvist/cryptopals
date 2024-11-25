from util import pkcs7_pad, pkcs7_unpad

assert (
    pkcs7_pad(b"YELLOW SUBMARINE", block_size=20) == b"YELLOW SUBMARINE\x04\x04\x04\x04"
)
assert pkcs7_unpad(b"YELLOW SUBMARINE\x04\x04\x04\x04") == b"YELLOW SUBMARINE"
