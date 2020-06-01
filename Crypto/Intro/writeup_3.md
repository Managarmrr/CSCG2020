# Intro to Crypto 3

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
**Attachments**: [intercepted-messages.txt](https://static.allesctf.net/challenges/810e996395ab6371a2d25af4b062b9482519c4917d05224dab1cf12047c8508d/intercepted-messages.txt)
[german_government.pem](https://static.allesctf.net/challenges/f01e1b92b877199a8118f503291db85a965744e2ef67bd5f080430a1fecdc319/german_government.pem)
[russian_government.pem](https://static.allesctf.net/challenges/e1fc88c972431b4c3e784455f9361201234db47aaffa586903748c9560b0d41f/russian_government.pem)
[us_government.pem](https://static.allesctf.net/challenges/f73ebf794a0d0c47f3222412a1995abc4d8d037ca18e15a45ec0784751b7b936/us_government.pem)  
**Description**:

This is an introductory challenge for beginners which want to dive into the
world of Cryptography. The three stages of this challenge will increase in
difficulty.

After a new potentially deadly disease first occurring in Wuhan, China, the
Chinese Corona Response Team sends messages to the remainder of the world.
However, to avoid disturbing the population, they send out this message
encrypted.

We have intercepted all messages sent by the Chinese government and provide you
with the public keys found on the governments' website.

Please, find out if we are all going to die!

## 2. Having a look

The `intercepted-messages.txt` file contains messages - presumable the same
plaintext - encrypted with each governments' key. The other `pem` files contain
thos public keys.

Upon checking the public key we notice that the exponent is rather small - 3.
Sadly the message appears to be long enough as taking the cube root does not
lead to plaintexts.

Assuming the message is the same for all keys we can perform an attack using
the `Chinese Remainder Theorem` (`CRT`) and take the cube root of the solution
to obtain the plaintext.

## 3. Exploit

The finished exploit looks like this:
```python
#!/usr/bin/env python3
import gmpy2
from Crypto.Util.number import long_to_bytes
from Crypto.PublicKey import RSA

from functools import reduce

def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod
 
def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a // b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1

usa = RSA.importKey(open('us_government.pem', 'r').read())
russia = RSA.importKey(open('russian_government.pem', 'r').read())
germany = RSA.importKey(open('german_government.pem', 'r').read())

# 0: germany, 1: usa, 2: russia
messages = [int(x.split(':')[1][1:])
    for x in open('intercepted-messages.txt', 'r').read().split('\n')
    if x != '']

n = [germany.n, usa.n, russia.n]
cand = chinese_remainder(n, messages)
plaintext = gmpy2.iroot(cand, 3)[0]
print(f'Got flag: {long_to_bytes(plaintext)}')
```

Running it we get the following output:
```
$ ./solve.py
Got flag: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACSCG{ch1nes3_g0vernm3nt_h4s_n0_pr0blem_w1th_c0ron4}'
```

Thus the flag for this challenge is:
`CSCG{ch1nes3_g0vernm3nt_h4s_n0_pr0blem_w1th_c0ron4}`

## 4. Mitigations

In order to avoid this kind of exploit, do not send the same message encrypted
with multiple public keys and please use larger exponents.
