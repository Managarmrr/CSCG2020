# win_eXPerience 2

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Extracting Data](#3-extracting-data)
4. [Mitigations](#4-mitigations)

## 1. Challenge

**Category**: `Misc`  
**Difficulty**: `Medium`  
**Author**: `TheVamp`  
**Attachments**: [memory.7z](https://static.allesctf.net/challenges/103c1efed0c8e950edf19e03468dd3b8aa4b25aa6f22364b46d701740e4b38aa/memory.7z)  
**Description**:

R3m3mb3r th3 g00d 0ld 1337 d4y5, wh3r3 cr4ckm35 4r3 wr1tt3n 1n l4ngu4g35, wh1ch
4r3 d34d t0d4y. H4v3 fun t0 f1nd th15 5m4ll g3m 1n th3 m3m0ry dump.

_Annoucement 1 (02.05.2020)): If you find a flag within a picuture, thats not a
flag! Its an artifact from an older revision of this challenge, please ignore!_

## 2. Having a look

In this challenge we are provided with what appears to be a `Windows` memory
dump. A very good tool to check them out is `volatility`, so let's use it.

## 3. Extracting data

Using `volatility` we can identify the system:

```
$ volatility -f memory.dmp imageinfo                                                                                  
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : VirtualBoxCoreDumpElf64 (Unnamed AS)
                     AS Layer3 : FileAddressSpace (/home/managarmr/CTF/2020/CSCG/Misc/win_eXPerience/memory.dmp)
                      PAE type : No PAE
                           DTB : 0x39000L
                          KDBG : 0x8054c760L
          Number of Processors : 1
     Image Type (Service Pack) : 2
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2020-03-22 18:30:56 UTC+0000
     Image local date and time : 2020-03-22 10:30:56 -0800
```

Cool. Now we can have a look at the process list:

```
$ volatility -f memory_1.dmp --profile=WinXPSP2x86 pslist                                                               
Volatility Foundation Volatility Framework 2.6.1
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x81bcca00 System                    4      0     53      262 ------      0                                                              
0x81a04da0 smss.exe                340      4      3       21 ------      0 2020-03-22 18:27:38 UTC+0000                                 
0x81a46928 csrss.exe               496    340      9      387      0      0 2020-03-22 18:27:39 UTC+0000                                 
0x81a41950 winlogon.exe            524    340     19      428      0      0 2020-03-22 18:27:39 UTC+0000                                 
0x8197eda0 services.exe            632    524     16      262      0      0 2020-03-22 18:27:39 UTC+0000                                 
0x81a2d810 lsass.exe               644    524     23      356      0      0 2020-03-22 18:27:39 UTC+0000                                 
0x81a0cda0 VBoxService.exe         792    632      9      118      0      0 2020-03-22 18:27:39 UTC+0000                                 
0x81a16500 svchost.exe             840    632     20      204      0      0 2020-03-22 18:27:39 UTC+0000                                 
0x81abf9a8 svchost.exe             928    632      9      259      0      0 2020-03-22 18:27:39 UTC+0000                                 
0x81abd0f0 svchost.exe            1024    632     67     1298      0      0 2020-03-22 18:27:39 UTC+0000                                 
0x8194dc70 svchost.exe            1076    632      6       74      0      0 2020-03-22 18:27:39 UTC+0000                                 
0x817da020 svchost.exe            1120    632     18      219      0      0 2020-03-22 18:27:39 UTC+0000                                 
0x817b33c0 explorer.exe           1524   1484     14      353      0      0 2020-03-22 18:27:40 UTC+0000                                 
0x817b2318 spoolsv.exe            1536    632     14      113      0      0 2020-03-22 18:27:40 UTC+0000                                 
0x81794608 VBoxTray.exe           1644   1524     12      122      0      0 2020-03-22 18:27:40 UTC+0000                                 
0x817cd690 ctfmon.exe             1652   1524      1       66      0      0 2020-03-22 18:27:40 UTC+0000                                 
0x81791020 msmsgs.exe             1660   1524      4      169      0      0 2020-03-22 18:27:40 UTC+0000                                 
0x8173ec08 CSCG_Delphi.exe        1920   1524      1       29      0      0 2020-03-22 18:27:45 UTC+0000                                 
0x8176c378 mspaint.exe             264   1524      4      102      0      0 2020-03-22 18:27:48 UTC+0000                                 
0x8172abc0 svchost.exe             548    632      8      129      0      0 2020-03-22 18:27:51 UTC+0000                                 
0x81759820 alg.exe                1176    632      6      100      0      0 2020-03-22 18:27:51 UTC+0000                                 
0x816e41f0 svchost.exe            1688    632      9       93      0      0 2020-03-22 18:28:00 UTC+0000                                 
0x816d8438 TrueCrypt.exe           200   1524      1       44      0      0 2020-03-22 18:28:02 UTC+0000                                 
0x81768310 wuauclt.exe            1300   1024      7      174      0      0 2020-03-22 18:28:35 UTC+0000                                 
0x817a9b28 wscntfy.exe            1776   1024      1       36      0      0 2020-03-22 18:28:51 UTC+0000                                 
0x816d8cd8 wpabaln.exe             988    524      1       66      0      0 2020-03-22 18:29:38 UTC+0000
```

`CSCG_Delphi` seems rather suspicious. And would coincide with the "oldschool"
part of the "old crackmes in dead languages".

Opening the executable in IDA we can immediately see some strings which look
suspiciously like `MD5` hashes - oldschool again. And indeed they are, cracking
them online was no trouble and returned the following results:

```
1efc99b6046a0f2c7e8c7ef9dc416323:dl0:MD5
25db3350b38953836c36dfb359db4e27:kc4rc:MD5PLAIN
40a00ca65772d7d102bb03c3a83b1f91:!3m:MD5
c129bd7796f23b97df994576448caa23:l00hcs:MD5
017efbc5b1d3fb2d4be8a431fa6d6258:1hp13d:0
```

Which are quite obviously reversed strings and result in the flag:
`CSCG{0ld_sch00l_d31ph1_cr4ck_m3!}`

## 4. Mitigations

There is no point in talking about mitigation in reversing challenges.
Although you could hash the whole flag with a newer algorithm.
