# Intro to Crypto 2

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Exploit](#3-exploit)
4. [Mitigations](#4-mitigations)


## 1. Challenge

**Category**: `Crypto`  
**Difficulty**: `Baby`  
**Author**: `black-simon`  
**Attachments**: [message.txt](https://static.allesctf.net/challenges/bfa25aea78856f259e6a97ed68eb00c078d4679a885b52b5a6154886872bf956/message.txt)
[pubkey.pem](https://static.allesctf.net/challenges/f17f1b0cc2d2f0466a15b9dc251c528e52abfc13db95e1cfd42a164ef32aabc7/pubkey.pem)  
**Description**:

This is an introductory challenge for beginners which want to dive into the
world of Cryptography. The three stages of this challenge will increase in
difficulty.

I learned my lesson from the mistakes made in the last challenge! Now p and q
are huge, I promise!

## 2. Having a look

The `message.txt` obviously contains the encrypted flag. The `pubkey.pem`
contains the public key. So let's just do the easy thing and check it on
`FactorDB` and sadly no luck this time, damn.

Well the next best thing is checking whether they are equal or close to each
other and it turns out that they indeed are close to each other. Making
factoring them using Eulers method trivial.

## 3. Exploit

The finished exploit looks like this:
```python
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
```

Running it we get the following output:
```
$ ./solve.py
Got flag: b'CSCG{Ok,_next_time_I_choose_p_and_q_random...}'
```

Thus the flag for this challenge is:
`CSCG{Ok,_next_time_I_choose_p_and_q_random...}`

## 4. Mitigations

1. In order to generate secure primes, they should be both be of high bitstrength.
2. Their euclidean distance should also be suitable large.

The first criteria was met in this case, though not the second one.
