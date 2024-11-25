import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs

from aes import ECB
from oracle import random_key
from util import pkcs7_pad, pkcs7_unpad, pretty_print_bytes

DISALLOWED = re.compile(r"[&=]")

query_string = "foo=bar&baz=qux&zap=zazzle"
test_query_dict = {
    "foo": "bar",
    "baz": "qux",
    "zap": "zazzle",
}


def parse_query_string(query_string: str) -> dict[str, str]:
    map = parse_qs(qs=query_string)
    return {k: v[0] for k, v in map.items()}


assert parse_query_string(query_string=query_string) == test_query_dict


def profile_for(email: str) -> str:
    data = {"email": DISALLOWED.sub("", email), "uid": 10, "role": "user"}

    return "&".join(f"{k}={v}" for k, v in data.items())


@dataclass
class ProfileOracle:
    key: bytes = field(default_factory=random_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        encoded_profile = profile_for(email=plaintext.decode())
        return ECB(key=self.key).encrypt(plaintext=encoded_profile.encode())

    def decrypt(self, ciphertext: bytes) -> bytes:
        return ECB(key=self.key).decrypt(ciphertext=ciphertext)

    def decrypt_and_parse(self, ciphertext: bytes) -> dict[str, str]:
        plaintext = pkcs7_unpad(self.decrypt(ciphertext=ciphertext))
        return parse_query_string(query_string=plaintext.decode())


if __name__ == "__main__":
    block_size = 16

    oracle = ProfileOracle()
    example_email = b"foo@bar.com"
    ct_example = oracle.encrypt(example_email)
    pt_example = oracle.decrypt(ciphertext=ct_example)

    # given the profile_for function output, the example input produces a query
    # string of length 34
    assert len(profile_for(example_email.decode())) == 34

    # ... which means 2 (34 % 16 => 2) input characters in the trailing block:
    # |e |r |0e|0e|0e|0e|0e|0e|0e|0e|0e|0e|0e|0e|0e|0e|
    trailing_block = pt_example[-block_size:]
    assert trailing_block == pkcs7_pad(b"er")
    print(f"{example_email.decode()} [decrypted]")
    pretty_print_bytes(pt_example, chunk_size=block_size, decode=True)

    # knowing this, it is easy to produce a block ending with "role=", followed by
    # a block that consists only of "user" and padding, by adding 2 bytes to the
    # input:
    padded_email = b"foooo@bar.com"
    ct_example_padded = oracle.encrypt(padded_email)
    pt_example_padded = oracle.decrypt(ciphertext=ct_example_padded)
    # |u |s |e |r |0c|0c|0c|0c|0c|0c|0c|0c|0c|0c|0c|0c|
    trailing_block = pt_example_padded[-block_size:]
    assert trailing_block == pkcs7_pad(b"user")

    print(f"{padded_email.decode()} [encrypted]")
    pretty_print_bytes(ct_example_padded, chunk_size=block_size)
    print(f"{padded_email.decode()} [decrypted]")
    pretty_print_bytes(pt_example_padded, chunk_size=block_size, decode=True)

    # now, the objective is to produce a clean block that contains "admin" followed
    # by padding:
    # |a |d |m |i |n |0b|0b|0b|0b|0b|0b|0b|0b|0b|0b|0b|
    crafted_block = pkcs7_pad(b"admin")
    print("crafted block")
    pretty_print_bytes(crafted_block, chunk_size=block_size, decode=True)

    # this can be done by ensuring the "email=..." length == block size
    # and appending the above record:
    partial_email = b"fooo@baar."
    assert len(b"email=" + partial_email) == block_size
    payload = partial_email + crafted_block

    ct_payload = oracle.encrypt(payload)

    # extract block 2
    encrypted_admin_block = ct_payload[block_size : block_size + block_size]
    # ... and manually create a new ciphertext:
    crafted_ct = ct_example_padded[:-block_size] + encrypted_admin_block

    print("crafted ciphertext")
    pretty_print_bytes(crafted_ct, chunk_size=block_size)

    decrypted_token = oracle.decrypt_and_parse(crafted_ct)
    print("decrypted token")
    print(decrypted_token)
    assert decrypted_token["role"] == "admin"
