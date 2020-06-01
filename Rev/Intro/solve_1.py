#!/usr/bin/env python3
from pwn import *

PASSWORD = 'y0u_5h3ll_p455'

# target = process('rev1')
target = remote('hax1.allesctf.net', 9600)

target.recvline_contains('password:')

log.info(f'Sending password: {PASSWORD}')
target.sendline(PASSWORD)

print(target.recvall().decode('utf-8'))
