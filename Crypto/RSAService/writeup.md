# RSA Service

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Solving the discrete logarithm](#3-solving-the-discrete-logarithm)
4. [Final solution](#4-final-solution)
5. [Mitigations](#5-mitigations)

## 1. Challenge

**Category**: `Crypto`  
**Difficulty**: `Hard`  
**Author**: `black-simon`  
**Attachments**: [server.py](https://static.allesctf.net/challenges/1869a6b554d2e465f9cdbcbf7294b77e67c6325d7e2c4e258099df188067e0ab/server.py)  
**Description**:

What did you say?

`nc hax1.allesctf.net 9400`

## 2. Having a look

For this challenge we are provided with a `server.py` file. Checking it out we
can see that in order to obtain the flag we need to provide a message and a
`pem` encoded private key, which will pass the following checks:

```python
key = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
assert key.check()
numbers = key.to_cryptography_key().private_numbers()

d = numbers.d
N = numbers.p * numbers.q

if pow(int.from_bytes(message, "big"), d, N) == int.from_bytes(question_to_ask, "big"):
    print("CSCG{DUMMY_FLAG}")
else:
    print("That was not kind enough!")
```

This seems trivial, but unfortunately for us our message will be replaces by
`b'Quack! Quack!'` regardless of what we do. So the problem boils down to:

- Generate a private RSA key
- The key must be valid (pass openssl checks)
- The key must decrypt `b'Quack! Quack!'` into `b'Hello! Can you give me the flag, please? I would really appreciate it!'`

## 3. Solving the discrete logarithm

So the challenge just asks us to solve the `discrete logarithm` problem, sure
nothing more trivial than this.

Well generically solving the `discrete logarithm` isn't really an option if you
didn't catch on to the sarcasm, but the challenge doesn't ask us to do it
_generically_, in fact it is nice enough to even let us pick which primes we
want, how nice. Thanks to the awesome people named `Roland Silver`,
`Stephen Pohlig` and `Martin Hellman` we can compute the discrete logarithm
for `finite abelian groups`, given that their order is `smooth`.

So how does this help us? Well we can create primes, such that `(x - 1)` is
smooth, meaning that the `discrete logarithms` for `p` and `q` can be calculated
efficiently. The only step that's left is to combine the two of them using the
`CRT` and we are done. Afterwards it's just a matter of generating the private
key with given `p`, `q` and `d` - which is trivial.

## 4. Final solution

The solution looks like this:

```python
#!/usr/bin/env sage

source = 6453808645099481754496697330465
target = 1067267517149537754067764973523953846272152062302519819783794287703407438588906504446261381994947724460868747474504670998110717117637385810239484973100105019299532993569

def find_smooth(root, bits, smooth_bits):
	while True:
		prod = 1
		while prod.nbits() < bits:
			prod *= random_prime(2^smooth_bits - 1)
		
		if not (prod + 1).is_prime():
			continue

		F = IntegerModRing(prod + 1)
		if not F(root).is_primitive_root():
			continue

		return prod + 1

p, q, e, d = 0, 0, 0, 0
primes = []
while True:
	p = find_smooth(source, target.nbits() // 2 + 1, 16)	
	if p in primes:
		continue
	
	print(f'Found new prime: {p}')
	if len(primes) == 0:
		primes.append(p)
		continue

	# Check all pairs
	for q in primes:
		if gcd(p - 1, q - 1) > 2:
			continue
		
		n = p*q
		phi = (p - 1) * (q - 1)
		if target > n:
			continue
		
		F_p = IntegerModRing(p)
		F_q = IntegerModRing(q)
		d_p = discrete_log(F_p(target), F_p(source))
		d_q = discrete_log(F_q(target), F_q(source))

		try:
			d = CRT([d_p, d_q], [p - 1, q - 1])
		except:
			continue

		if gcd(d, phi) > 1:
			continue
		
		e = inverse_mod(d, phi)
		break
	
	if e != 0:
		break

	primes.append(p)


print(f'\np = {p}\nq = {q}\nd = {d}\ne = {e}\nn = p*q')
```

and produces the following output:

```
$ time ./solve.sage
Found new prime: 2420224477575443310440328600179722291750879519029823444741925489154763420873899905519
Found new prime: 13216592923579023259927510014086218724494026737677502433260890692696949639863148741337483
Found new prime: 13652460225238158445913555436505678607368617241848360437498299123891545267017196759887
p = 13652460225238158445913555436505678607368617241848360437498299123891545267017196759887
q = 2420224477575443310440328600179722291750879519029823444741925489154763420873899905519
d = 431257864379705271812229118094445987736572813043541086140552818143042259972142423891498864009988912357327198283860107056765659767851094022163875373849501016625699779847
e = 15508707214745388893076447088375680738501639431745811447384793859429227099470407957508334259147088339015904755390911026657526806607992020563092472132775474941780845785823
n = p*q
./solve.sage  6.59s user 0.09s system 98% cpu 6.776 total
```

With the corresponding python script:

```python
#!/usr/bin/env python3
from pwn import remote
from Crypto.PublicKey import RSA

p = 13652460225238158445913555436505678607368617241848360437498299123891545267017196759887
q = 2420224477575443310440328600179722291750879519029823444741925489154763420873899905519
d = 431257864379705271812229118094445987736572813043541086140552818143042259972142423891498864009988912357327198283860107056765659767851094022163875373849501016625699779847
e = 15508707214745388893076447088375680738501639431745811447384793859429227099470407957508334259147088339015904755390911026657526806607992020563092472132775474941780845785823
n = p*q

key = RSA.construct((n, e, d))

target = remote('hax1.allesctf.net', 9400)
target.recvline_contains('PEM format:')
target.sendline(key.exportKey())
target.sendline('')
target.sendline('')
print(target.recvall().decode('utf-8'))
```

Running the script return the flag:

```
$ ./solve.py
[+] Opening connection to hax1.allesctf.net on port 9400: Done
[+] Receiving all data: Done (147B)
[*] Closed connection to hax1.allesctf.net port 9400
Now give me your message: Did you say 'Quack! Quack!'? I can't really understand you, the ducks are too loud!
CSCG{下一家烤鴨店在哪裡？}
```

`CSCG{下一家烤鴨店在哪裡？}`

## 5. Mitigations

There aren't really any mitigations, but you could prevent an attacker from
picking the used private key - as it makes it possible to generate a private key
matching any given pair of encrypted/decrypted or plain/signed data.
