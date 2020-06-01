#!/usr/bin/env python3
from pwn import *

# Thanks, Ghidra
OBFUS_PASS = b'lp`7a<qLw\x1ekHopt(f-f*,o}V\x0f\x15J'
PASSWORD = ''.join(
	[chr((y + 2) ^ x) for x, y in
		enumerate(OBFUS_PASS, start=10)])

# target = process('rev3')
target = remote('hax1.allesctf.net', 9602)

target.recvline_contains('password:')

log.info(f'Sending password: {PASSWORD}')
target.sendline(PASSWORD)

print(target.recvall().decode('utf-8'))
