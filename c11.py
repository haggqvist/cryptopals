from oracle import RandomOracle, detect_ecb_or_cbc

oracle = RandomOracle()

for n in range(30):
    detected_mode = detect_ecb_or_cbc(encryption_oracle=oracle)
    assert detected_mode == oracle.last_mode
