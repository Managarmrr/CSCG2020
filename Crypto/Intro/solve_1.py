#!/usr/bin/env python3
import gmpy2
from Crypto.Util.number import long_to_bytes
from Crypto.PublicKey import RSA

key = RSA.importKey(open('pubkey.pem', 'rb').read())

# Factor DB
p = 622751
q = key.n // p
phi = (p - 1) * (q - 1)

_, d, _ = gmpy2.gcdext(key.e, phi)

ciphertext = int(open('message.txt', 'rb').read())
plaintext = pow(ciphertext, d, key.n)
print(f'Got flag: {long_to_bytes(plaintext)}')
