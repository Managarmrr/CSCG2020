# StayWoke Shop

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Mitigations](#3-mitigations)

## 1. Challenge

**Category**: `Web`  
**Difficulty**: `Easy`  
**Author**: `pspaul`  
**Description**:

Are you missing some essential items that were sold out in your local
supermarket? You can easily stock up on these in my shop:

http://staywoke.hax1.allesctf.net/

## 2. Having a look

This is a webshop with a hidden item called flag at
http://staywoke.hax1.allesctf.net/products/1. Unfortunately it is pretty
expensive and we don't have any `w0kecoins`. But the newsticker at the top
informs us of an ongoing sale which allows us to save 20% by using the coupon
code `I<3CORONA`. Funny enough we can add the flag multiple times - let's say
20 times, apply the coupon and remove 19 flags. The coupon value stays the same
allowing us to buy the flag by inputing an arbitrary account.

This lets us obtain the flag trivially.

Flag: `CSCG{c00l_k1ds_st4y_@_/home/}`

## 3. Mitigations

In order to mitigate this exploit the value of the coupon should be applied
when paying, not to the basket itself.
