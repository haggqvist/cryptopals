from xor import repeating_key


s = "Burning 'em, if you ain't quick and nimble\n"
s += "I go crazy when I hear a cymbal"

expect = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
expect += "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

c = b"ICE"

o = repeating_key(s.encode(), c)

print(o.hex())
