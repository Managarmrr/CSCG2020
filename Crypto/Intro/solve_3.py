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

#print(usa.e)
#print(russia.e)
#print(germany.e)

# 0: germany, 1: usa, 2: russia
messages = [int(x.split(':')[1][1:])
    for x in open('intercepted-messages.txt', 'r').read().split('\n')
    if x != '']

n = [germany.n, usa.n, russia.n]
cand = chinese_remainder(n, messages)
plaintext = gmpy2.iroot(cand, 3)[0]
print(f'Got flag: {long_to_bytes(plaintext)}')
