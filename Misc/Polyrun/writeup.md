# Polyrun

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Mitigations](#3-mitigations)

## 1. Challenge

**Category**: `Misc`  
**Difficulty**: `Easy`  
**Author**: `explo1t`  
**Attachments**: [run.pl](https://static.allesctf.net/challenges/06ab64a75dfb6fbda170b4e15b58a93daaf4e27ceb4a5cab22ed37c6f69ed80e/run.pl)  
**Description**:

Script.VeryBogusExecution

## 2. Having a look

We are provided with what seems to be a `Perl` script. But the challenge title
hints at this possibly being a `polyglot`.

After going through pretty much all `Esolangs` which have `'` as a comment
indicator we can finally remember the existence of `VBE` scripts - which are
encoded `VBS` scripts. Why, Microsoft, why? Well after downloading a decoder
we are able to properly decode the script:

```vbs
' CSCG{This_is_the_flag_yo}
MsgBox "CSCG[THIS_NOT_REAL_FLAG]", VBOKOnly, "Nope"
```

Resulting in the flag: `CSCG{This_is_the_flag_yo}`

## 3. Mitigations

There really isn't a point in talking about mitigation regarding this challenge.
