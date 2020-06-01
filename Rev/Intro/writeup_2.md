# Intro to Reversing 2

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Final exploit](#3-final-exploit)
4. [Mitigations](#4-mitigations)


## 1. Challenge

**Category**: `Reverse Engineering`  
**Difficulty**: `Baby`  
**Author**: `0x4d5a`  
**Attachments**: [intro_rev2.zip](https://static.allesctf.net/challenges/fa402a66e302289d0babf1dfe98c81925152b5bc3c440b04e6d9aa37a2a8cdf7/intro_rev2.zip)  
**Description**:

This is a introductory challenge for beginners which are eager to learn reverse
engineering on linux. The three stages of this challenge will increase in
difficulty. But for a gentle introduction, we have you covered: Check out the
[video of LiveOverflow](https://www.youtube.com/watch?v=28JHPOUZvDw) or follow
the [authors step by step guide](https://static.allesctf.net/Tutorial_Intro_rev.html)
to solve the first part of the challenge.

Once you solved the challenge locally, grab your real flag at:
`nc hax1.allesctf.net 9601`

_Note: Create a dummy flag file in the working directory of the rev1 challenge.
The real flag will be provided on the server_

## 2. Having a look

Upon checking the zip file we received we can see that a binary was provided to
us:

```
$ unzip -l intro_rev2.zip 
Archive:  intro_rev2.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     8712  2020-03-02 01:07   rev2
       33  2020-03-02 02:58   flag
---------                     -------
     8745                     2 files
```

We can not find anything resembling a password within the strings, so after
looking at the `main()` in `Ghidra` we can tell that it has been obfuscated:
```c
  puts("Give me your password: ");
  user_input_len = read(0,user_input,0x1f);
  user_input[(int)user_input_len + -1] = '\0';
  i = 0;
  while (i < (int)user_input_len + -1) {
    user_input[i] = user_input[i] + -0x77;
    i = i + 1;
  }
  iVar1 = strcmp(user_input,s__00100ab0);
  if (iVar1 == 0) {
    puts("Thats the right password!");
    printf("Flag: %s",flagBuffer);
  }
```

Deobfuscating the password is trivial in this case.

## 3. Final exploit

Our final exploit looks like this:
```python
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
```

Running it we get the following output:
```
[+] Opening connection to hax1.allesctf.net on port 9601: Done
[*] Sending password: sta71c_tr4n5f0rm4710n_it_is
[+] Receiving all data: Done (83B)
[*] Closed connection to hax1.allesctf.net port 9601
Thats the right password!
Flag: CSCG{1s_th4t_wh4t_they_c4ll_on3way_transf0rmati0n?}
```

Thus the flag for this challenge is
`CSCG{1s_th4t_wh4t_they_c4ll_on3way_transf0rmati0n?}`

## 4. Mitigations

There is not really a point in talking about mitigations when it comes to
reversing, but I suppose you could make it harder on everybody. Also in this
particular case one would be better off just hashing a sufficiently strong
password.
