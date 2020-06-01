#!/usr/bin/env python3
import gmpy2
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes

key = RSA.importKey(open('pubkey.pem', 'rb').read())
ciphertext = int(open('message.txt', 'rb').read())

def fermat(n):
	p = 0
	q = 0
	found = False
	a = gmpy2.isqrt(n)
	while a*a < n:
		a += 1

	while not found:
		x = gmpy2.isqrt(a*a - n)
		p = (a - x)
		q = (a + x)
		if p * q == n:
			break
		else:
			a += 1
	return (p, q)

p, q = fermat(key.n)
phi = (p - 1) * (q - 1)
_, d, _ = gmpy2.gcdext(key.e, phi)

plaintext = pow(ciphertext, d, key.n)
print(f'Got flag: {long_to_bytes(plaintext)}')
