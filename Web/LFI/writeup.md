# Local Fun Inclusion

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Mitigations](#3-mitigations)

## 1. Challenge

**Category**: `Web`  
**Difficulty**: `Easy`  
**Author**: `0x4d5a`  
**Description**:

Recently i learned how to code in PHP. There are cool tutorials for file uploads
around! [Imgur Memes](https://i.imgur.com/OV86lKu.png) have no chance vs. my
cool image sharing website!

Check it out at: `http://lfi.hax1.allesctf.net:8081/`

## 2. Having a look

The website allows us to upload any image and will display it for us by giving
us a link with which we are able to view it. For example
http://lfi.hax1.allesctf.net:8081/index.php?site=view.php&image=uploads/5fe7c042101a7c69171cce58fd425684.png.
The link seems weird though - why the `site` parameter?

This reeks of a `Local File Inclusion` so we upload a shell with the `gif`
header (`GIF89a`) and include it by removing the `view.php&image=` of the `URL`.

This indeed provides us with a functioning shell - allowing us to read
`flag.php`:

```php
<?php

$FLAG = "CSCG{G3tting_RCE_0n_w3b_is_alw4ys_cool}";
```

Thus the flag is `CSCG{G3tting_RCE_0n_w3b_is_alw4ys_cool}`.

## 3. Mitigations

Use a whitelist of allowed `site` values - or even better change your code to
not use a system like that. Also use more sophisticated methods of validating
whether a file is an image or not.
