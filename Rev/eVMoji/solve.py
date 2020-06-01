#!/usr/bin/env python3
import z3
from pwn import *

from vm import VM

file = open('./code.bin', 'rb')
data = file.read(0x200)
code = file.read()
file.close()

vm = VM(code, data)
# vm.transpile()
# vm.run(verbose=True)
# vm.run(input=b'n3w_ag3_v1rtu4liz4t1on_', verbose=True)

def crc32(input, round_xor, final_xor):
	state = z3.BitVecVal(0xffffffff, 32)

	for i in range(0, 32):
		state = z3.If(
			state & 1 == z3.LShR(input, i) & 1,
			z3.LShR(state, 1),
			z3.LShR(state, 1) ^ round_xor)

	return state ^ final_xor

s = z3.Solver()
input = z3.BitVec('input', 32)
round_xor = u32(data[0x80:0x84])
final_xor = u32(data[0x88:0x8c])
s.add(crc32(input, round_xor, final_xor) == 0)

if s.check() == z3.sat:
	suffix = int(str(s.model()[input]))
	vm.run(input=b'n3w_ag3_v1rtu4liz4t1on_' + p32(suffix), silent=False)
