#!/usr/bin/env python3
from pwn import *

# Thanks, Ghidra
OBFUS = 'FC,FD,EA,C0,BA,EC,E8,FD,FB,BD,F7,BE,EF,B9,FB,F6,BD,C0,BA,B9,F7,E8,F2,FD,E8,F2,FC'
PASSWORD = ''.join(
	[chr((int(x, 16) + 0x77) & 0xff) for x in OBFUS.split(',')])
	
# target = process('rev2')
target = remote('hax1.allesctf.net', 9601)

target.recvline_contains('password:')

log.info(f'Sending password: {PASSWORD}')
target.sendline(PASSWORD)

print(target.recvall().decode('utf-8'))
