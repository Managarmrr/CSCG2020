#!/usr/bin/env python3
from pwn import *


class VM(object):
	_code = bytearray()
	_data = bytearray()
	__data = bytearray()

	_input = bytearray()

	_run_flag = False
	_silent_mode = True
	_verbose_mode = False
	_transpile_mode = False

	ip = 0

	def __init__(self, code, data):
		self._code = code.decode('UTF-8')
		self.__data = data

		self.OPCODES = {
			'💪': self.push_immediate,
			'✏': self.write,
			'📖': self.read,
			'🦾': self.push_data_byte,
			'🔀': self.xor,
			'✅': self.or_,
			'🤔': self.je,
			'💀': self.exit,
			'🌠': self.push_data_long,
			'‼': self.duplicate,
			'➕': self.bitmask,
			'➡': self.shift
		}

	def reset(self):
		self._data[:] = self.__data
		self._stack = []
		self._run_flag = True

		self.ip = 0

	def _run(self):
		while self._run_flag and self.ip < len(self._code):
			opcode = self._code[self.ip]
			if opcode not in self.OPCODES:
				log.warning(f'Unimplemented opcode: {opcode}')
				self._run_flag = False
				continue

			self.OPCODES[opcode](self.ip)

	def run(self, input=b'', silent=True, verbose=False):
		self.reset()
		self._input = input
		self._silent_mode = silent
		self._verbose_mode = verbose
		self._transpile_mode = False
		self._run()

	def transpile(self):
		self.reset()
		self._transpile_mode = True
		self._run()

	# Helper functions

	def to_virt_addr(self, real_addr):
		return len(self._code[:real_addr].encode('UTF-8'))

	def to_real_addr(self, virt_addr):
		return len(self._code.encode('utf-8')[:virt_addr].decode('utf-8'))

	def push(self, val):
		self._stack.append(val)

	def pop(self):
		if (len(self._stack) == 0):
			log.warning('Attempt to pop from empty stack')
			raise IndexError()

		val = self._stack[-1]
		self._stack = self._stack[:-1]
		return val

	def decode_immediate(self):
		res = 0
		for _ in range(0, 3):
			y = self._code[self.ip]
			x = self._code[self.ip + 3]
			self.ip += 6
			res += int(int(x) ** int(y))
		return res

	# Opcodes

	def push_immediate(self, address):
		self.ip += 1

		imm = self.decode_immediate()
		self.push(imm)

		if self._transpile_mode or self._verbose_mode:
			log.info(f'{address:04x}\tpushil  {imm:08x}')

	def write(self, address):
		self.ip += 2

		size = self.pop()
		str_pos = self.pop()

		if self._transpile_mode or self._verbose_mode:
			log.info(f'{address:04x}\twrite   data[{hex(str_pos)}]:{hex(size)}')
		
		if not self._silent_mode and not self._transpile_mode:
			log.success('> ' + self._data[str_pos:str_pos + size].decode('UTF-8'))

	def read(self, address):
		self.ip += 1

		size = self.pop()
		buf_pos = self.pop()

		if self._transpile_mode or self._verbose_mode:
			log.info(f'{address:04x}\tread    data[{hex(buf_pos)}]:{hex(size)}')
		
		if not self._transpile_mode:
			read_size = len(self._input)
			read_size = size if size < read_size else read_size
			self._data[buf_pos:buf_pos + read_size] = self._input[:read_size]
			
			if not self._silent_mode:
				log.success(f'< {self._input[:read_size]}')

	def push_data_byte(self, address):
		self.ip += 1

		imm = self.decode_immediate()
		val = self._data[imm]

		self.push(val)

		if self._transpile_mode:
			log.info(f'{address:04x}\tpushb   data[{hex(imm)}]')
		elif self._verbose_mode:
			log.info(f'{address:04x}\tpushb   {val:02x}')

	def xor(self, address):
		self.ip += 1

		op1 = self.pop()
		op2 = self.pop()
		res = op1 ^ op2
		self.push(res)

		if self._transpile_mode:
			log.info(f'{address:04x}\txor')
		elif self._verbose_mode:
			char = ''
			try:
				char = f' ({chr(res)})'
			except:
				pass
			log.info(f'{address:04x}\txor     {op1:08x}, {op2:08x} # {res:08x}{char}')

	def or_(self, address):
		self.ip += 1

		op1 = self.pop()
		op2 = self.pop()
		res = op1 | op2
		self.push(res)

		if self._transpile_mode:
			log.info(f'{address:04x}\tor')
		elif self._verbose_mode:
			log.info(f'{address:04x}\tor      {op1:08x}, {op2:08x} # {res:08x}')

	def je(self, address):
		self.ip += 1

		imm = self.decode_immediate()
		dst = self.to_virt_addr(self.ip) + imm
		real_dst = self.to_real_addr(dst)

		op1 = self.pop()
		op2 = self.pop()

		if self._transpile_mode:
			log.info(f'{address:04x}\tje      {real_dst:04x}\n\n')
		elif self._verbose_mode:
			log.info(f'{address:04x}\tje      {real_dst:04x} # {op1:08x} == {op2:08x}')

		if not self._transpile_mode and op1 == op2:
			self.ip = real_dst

	def exit(self, address):
		self.ip += 1

		if self._transpile_mode or self._verbose_mode:
			log.info(f'{address:04x}\texit\n\n')
		
		if not self._transpile_mode:
			self._run_flag = False

	def push_data_long(self, address):
		self.ip += 1

		imm = self.decode_immediate()
		val = u32(self._data[imm:imm + 4])
		self.push(val)

		if self._transpile_mode:
			log.info(f'{address:04x}\tpushl   data[{hex(imm)}]')
		elif self._verbose_mode:
			log.info(f'{address:04x}\tpushl   {val:08x}')

	def duplicate(self, address):
		self.ip += 2

		op = self.pop()
		self.push(op)
		self.push(op)

		if self._transpile_mode:
			log.info(f'{address:04x}\tdupl')
		elif self._transpile_mode:
			log.info(f'{address:04x}\tdupl    # {op:08x}')

	def bitmask(self, address):
		self.ip += 1

		op = self.pop()
		self.push(op & 1)

		if self._transpile_mode:
			log.info(f'{address:04x}\tbitmask')
		elif self._transpile_mode:
			log.info(f'{address:04x}\tbitmask # {op:08x} => {op&1}')

	def shift(self, address):
		self.ip += 2

		imm = self.decode_immediate()

		op = self.pop()
		res = op >> (imm & 0x1f)
		self.push(res)

		if self._transpile_mode:
			log.info(f'{address:04x}\tshr     {imm & 0x1f}')
		elif self._verbose_mode:
			log.info(f'{address:04x}\tshr     {imm & 0x1f} # {op:08x} => {res:08x}')
