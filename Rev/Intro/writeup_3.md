# Intro to Reversing 3

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
**Attachments**: [intro_rev3.zip](https://static.allesctf.net/challenges/41b527d7ae79a9f584fd0342a93eee55867852c5418bfd0bf7d405be899ba0b0/intro_rev3.zip)  
**Description**:

This is a introductory challenge for beginners which are eager to learn reverse
engineering on linux. The three stages of this challenge will increase in
difficulty. But for a gentle introduction, we have you covered: Check out the
[video of LiveOverflow](https://www.youtube.com/watch?v=28JHPOUZvDw) or follow
the [authors step by step guide](https://static.allesctf.net/Tutorial_Intro_rev.html)
to solve the first part of the challenge.

Once you solved the challenge locally, grab your real flag at:
`nc hax1.allesctf.net 9602`

_Note: Create a dummy flag file in the working directory of the rev1 challenge.
The real flag will be provided on the server_

## 2. Having a look

Upon checking the zip file we received we can see that a binary was provided to
us:

```
$ unzip -l intro_rev3.zip 
Archive:  intro_rev3.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     8712  2020-03-02 01:07   rev3
       33  2020-03-02 02:58   flag
---------                     -------
     8745                     2 files
```

We can not find anything resembling a password within the strings, so after
looking at the `main()` in `Ghidra` we can tell that it has been obfuscated:
```c
  puts("Give me your password: ");
  user_input_len = read(0,user_input,0x1f);
  user_input[(int)user_input_len + -1] = 0;
  i = 0;
  while (i < (int)user_input_len + -1) {
    user_input[i] = user_input[i] ^ (char)i + 10U;
    user_input[i] = user_input[i] - 2;
    i = i + 1;
  }
  iVar1 = strcmp((char *)user_input,"lp`7a<qLw\x1ekHopt(f-f*,o}V\x0f\x15J");
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
OBFUS_PASS = b'lp`7a<qLw\x1ekHopt(f-f*,o}V\x0f\x15J'
PASSWORD = ''.join(
	[chr((y + 2) ^ x) for x, y in
		enumerate(OBFUS_PASS, start=10)])

# target = process('rev3')
target = remote('hax1.allesctf.net', 9602)

target.recvline_contains('password:')

log.info(f'Sending password: {PASSWORD}')
target.sendline(PASSWORD)

print(target.recvall().decode('utf-8'))
```

Running it we get the following output:
```
[+] Opening connection to hax1.allesctf.net on port 9602: Done
[*] Sending password: dyn4m1c_k3y_gen3r4t10n_y34h
[+] Receiving all data: Done (94B)
[*] Closed connection to hax1.allesctf.net port 9602
Thats the right password!
Flag: CSCG{pass_1_g3ts_a_x0r_p4ss_2_g3ts_a_x0r_EVERYBODY_GETS_A_X0R}
```

Thus the flag for this challenge is
`CSCG{pass_1_g3ts_a_x0r_p4ss_2_g3ts_a_x0r_EVERYBODY_GETS_A_X0R}`

## 4. Mitigations

There is not really a point in talking about mitigations when it comes to
reversing, but I suppose you could make it harder on everybody. Also in this
particular case one would be better off just hashing a sufficiently strong
password.
