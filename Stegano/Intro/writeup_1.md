# Intro to Stegano 1

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Mitigations](#3-mitigations)

## 1. Challenge

**Category**: `Stegano`  
**Difficulty**: `Baby`  
**Author**: `explo1t`  
**Attachments**: [chall.jpg](https://static.allesctf.net/challenges/8df00cf74623f06bd322a627d1e37937678ef05f4a7a130a133eeb4c1480ca95/chall.jpg)  
**Description**:

This is an introductory challenge for the almighty steganography challenges. The
three stages contain very different variants of hidden information. Find them!

## 2. Having a look

We are provided with an image it appears. Running `strings` on it returns an
interesting one: `alm1ghty_st3g4n0_pls_g1v_fl4g`. Using the standard stegano
tool `steghide` we can extract the flag:

```
$ steghide extract -sf chall.jpg
```

`CSCG{Sup3r_s3cr3t_d4t4}`

## 3. Mitigations

There is no point in talking about mitigation in stegano challenges.
I suppose you could share your password securely out-of-band.
