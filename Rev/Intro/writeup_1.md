# Intro to Reversing 1

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
**Attachments**: [intro_rev1.zip](https://static.allesctf.net/challenges/21f57d226db95b63e46d9c68f2c3316e9ec09ffc85a3c2614d3437b5267f2528/intro_rev1.zip)  
**Description**:

This is a introductory challenge for beginners which are eager to learn reverse
engineering on linux. The three stages of this challenge will increase in
difficulty. But for a gentle introduction, we have you covered: Check out the
[video of LiveOverflow](https://www.youtube.com/watch?v=28JHPOUZvDw) or follow
the [authors step by step guide](https://static.allesctf.net/Tutorial_Intro_rev.html)
to solve the first part of the challenge.

Once you solved the challenge locally, grab your real flag at:
`nc hax1.allesctf.net 9600`

_Note: Create a dummy flag file in the working directory of the rev1 challenge.
The real flag will be provided on the server_

## 2. Having a look

Upon checking the zip file we received we can see that a binary was provided to
us:

```
$ unzip -l intro_rev1.zip 
Archive:  intro_rev1.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     8712  2020-03-02 01:07   rev1
       33  2020-03-02 02:58   flag
---------                     -------
     8745                     2 files
```

Upon checking the strings of the binary we can find a rather peculiar one:
```
$ strings ./rev1
[...snip...]
[]A\A]A^A_
Give me your password: 
y0u_5h3ll_p455
Thats the right password!
Flag: %s
Thats not the password!
[...snip...]
```

And as it turns out this really is the required password - fair enough for an
introductory challenge.

## 3. Final exploit

Our final exploit looks like this:
```python
#!/usr/bin/env python3
from pwn import *

PASSWORD = 'y0u_5h3ll_p455'

# target = process('rev1')
target = remote('hax1.allesctf.net', 9600)

target.recvline_contains('password:')

log.info(f'Sending password: {PASSWORD}')
target.sendline(PASSWORD)

print(target.recvall().decode('utf-8'))
```

Running it we get the following output:
```
[+] Opening connection to hax1.allesctf.net on port 9600: Done
[*] Sending password: y0u_5h3ll_p455
[+] Receiving all data: Done (61B)
[*] Closed connection to hax1.allesctf.net port 9600
Thats the right password!
Flag: CSCG{ez_pz_reversing_squ33zy}
```

Thus the flag for this challenge is `CSCG{ez_pz_reversing_squ33zy}`

## 4. Mitigations

There is not really a point in talking about mitigations when it comes to
reversing, but I suppose you could make it harder on everybody. Also in this
particular case one would be better off just hashing a sufficiently strong
password.
