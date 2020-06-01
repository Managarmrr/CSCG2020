# Intro to Crypto 1

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
**Attachments**: [message.txt](https://static.allesctf.net/challenges/a44c53fcd030d54b39aaec4dd1d98313b3c9ace82c82d60bbeda5c76c08b2c07/message.txt)
[pubkey.pem](https://static.allesctf.net/challenges/6ab79d44f4988bab336ef6e99a8b6a78fd09b6b806304482b705690d83c191b8/pubkey.pem)  
**Description**:

This is an introductory challenge for beginners which want to dive into the
world of Cryptography. The three stages of this challenge will increase in
difficulty. For an introduction to the first challenge visit the authors
[step by step guide](https://static.allesctf.net/Intro_Crypto.html).

For my new RSA key I used my own SecurePrimeService which definitely generates a
HUGE prime!

## 2. Having a look

The `message.txt` obviously contains the encrypted flag. The `pubkey.pem`
contains the public key. So let's just do the easy thing and check it on
`FactorDB` and surprisingly enough the modulus has been factored already:
[622751 · 1658423516...29](http://factordb.com/index.php?query=10327849034940138613515485956077213322791085874638285662823764630659653931824178919168344401508423966366637831067655701114352106747323628144645384205073278784870804834942988268503504130770762781798270763453272421050209487483563600870343875197428105079394315585993355808937811229959083289653056248770988647762812998870912510238393368777882358059256678052653963583286245796285737035786447522814310717433588049686223718247661713594680120785280795132759253149754143640871380226770164628599577669124463514838464342769690232097283333816896581904763736283142031118073027496197756777460403007359764250621763279762041468943079)

## 3. Exploit

After factoring the modulus developing the exploit is trivial:
```python
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
```

Running it we get the following output:
```
$ ./solve.py
Got flag: b'CSCG{factorizing_the_key=pr0f1t}'
```

Thus the flag for this challenge is: `CSCG{factorizing_the_key=pr0f1t}`

## 4. Mitigations

In order to generate secure primes, they should be both be of high bitstrength.
Their euclidean distance should also be suitable large.
