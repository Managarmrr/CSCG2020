# win_eXPerience 1

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Extracting Data](#3-extracting-data)
4. [Mitigations](#4-mitigations)

## 1. Challenge

**Category**: `Misc`  
**Difficulty**: `Easy`  
**Author**: `TheVamp`  
**Attachments**: [memory.7z](https://static.allesctf.net/challenges/103c1efed0c8e950edf19e03468dd3b8aa4b25aa6f22364b46d701740e4b38aa/memory.7z)  
**Description**:

R3m3mb3r th3 g00d 0ld 1337 d4y5, wh3r3 3ncrypt10n t00l5 4r3 u53d, wh1ch 4r3 d34d
t0d4y 4nd r3c0mm3nd b1tl0ck3r. H4v3 fun t0 f1nd th15 5m4ll g3m 1n th3 m3m0ry
dump.

_Annoucement 1: If you find a flag within a picuture, thats not a flag! Its an
artifact from an older revision of this challenge, please ignore!_

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

`Truecrypt` seems rather suspicious. Let's check the state of `Truecrypt`,
luckily `volatility` includes `TrueCrypt` support.

```
$ volatility -f memory_1.dmp --profile=WinXPSP2x86 truecryptsummary                                                     
Volatility Foundation Volatility Framework 2.6.1
Process              TrueCrypt.exe at 0x816d8438 pid 200
Service              truecrypt state SERVICE_RUNNING
Kernel Module        truecrypt.sys at 0xf7036000 - 0xf706d000
Symbolic Link        E: -> \Device\TrueCryptVolumeE mounted 2020-03-22 18:30:32 UTC+0000
Symbolic Link        Volume{93193a72-6c5c-11ea-a09c-080027daee79} -> \Device\TrueCryptVolumeE mounted 2020-03-22 18:28:42 UTC+0000
Symbolic Link        E: -> \Device\TrueCryptVolumeE mounted 2020-03-22 18:30:32 UTC+0000
File Object          \Device\TrueCryptVolumeE\$LogFile at 0x16d9c48
File Object          \Device\TrueCryptVolumeE\$BitMap at 0x1706100
File Object          \Device\TrueCryptVolumeE\password.txt at 0x1717be8
File Object          \Device\TrueCryptVolumeE\$Directory at 0x1718190
File Object          \Device\TrueCryptVolumeE\$Mft at 0x1797e80
File Object          \Device\TrueCryptVolumeE\$MftMirr at 0x185cb80
File Object          \Device\TrueCryptVolumeE\flag.zip at 0x1a3c7e8
File Object          \Device\TrueCryptVolumeE\$Mft at 0x1a85940
File Object          \Device\TrueCryptVolumeE\$Directory at 0x1ae55a0
Driver               \Driver\truecrypt at 0x19d0b10 range 0xf7036000 - 0xf706cb80
Device               TrueCryptVolumeE at 0x8172fa48 type FILE_DEVICE_DISK
Container            Path: \??\C:\Program Files\TrueCrypt\true.dmp
Device               TrueCrypt at 0x816d4be0 type FILE_DEVICE_UNKNOWN
```

It appears as if the device was still unlocked, allowing us to simply dump
`password.txt` and `flag.zip`. Resulting in a passphrase
(`BorlandDelphiIsReallyCool`) and a flag: 
`CSCG{c4ch3d_p455w0rd_fr0m_0p3n_tru3_cryp1_c0nt41n3r5}`

## 4. Mitigations

In order to mitigate this kind of attack you should **always** close containers
after you are done with them.
