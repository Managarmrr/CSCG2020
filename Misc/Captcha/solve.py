#!/usr/bin/env python3

import json
import os
import re
import requests
import time

from base64 import b64decode

ALPHABET = 'N0T67D9E8ZSA4GRFB5IH2CWKPJUQ3VMYX1L'

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
