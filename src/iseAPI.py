"""
Copyright (c) 2020 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

Steps required before accessing pxGrid supported services:

	Name 				Description
1 	AccountActivate 	Activate once at consumer startup
2 	ServiceLookup 		Get properties like URLs, topic... etc
3 	AccessSecret 		Get unique secret between 2 nodes
"""
import ssl
import json
import base64
import requests
import urllib.request
from requests.auth import HTTPBasicAuth


def get_ssl_context(config):
	context = ssl.create_default_context()
	if config['clientcert'] is not None:
		context.load_cert_chain(certfile=config['clientcert'],
                                keyfile=config['clientkey'],
                                password=config['clientkeypassword'])
	context.load_verify_locations(cafile=config['servercert'])
	return context


def pxgrid_account_activate(config):
	url = 'https://{}:8910/pxgrid/control/AccountActivate'.format(config['hostname'])
	payload = {}

	json_string = json.dumps(payload)
	# print("pxgrid url=" + url)
	# print('  request=' + json_string)

	handler = urllib.request.HTTPSHandler(context=get_ssl_context(config))
	opener = urllib.request.build_opener(handler)
	rest_request = urllib.request.Request(url=url, data=str.encode(json_string))

	rest_request.add_header('Content-Type', 'application/json')
	rest_request.add_header('Accept', 'application/json')

	b64 = base64.b64encode(
		(config['nodename'] + ':' + config['password']).encode()).decode()
	rest_request.add_header('Authorization', 'Basic ' + b64)
	rest_response = opener.open(rest_request)
	response = rest_response.read().decode()
	# print('  response=' + response)
	return json.loads(response)


def pxgrid_access_secret(config, peer_node_name):
	url = 'https://{}:8910/pxgrid/control/AccessSecret'.format(config['hostname'])
	payload = {'peerNodeName': peer_node_name}

	json_string = json.dumps(payload)
	# print("pxgrid url=" + url)
	# print('  request=' + json_string)

	handler = urllib.request.HTTPSHandler(context=get_ssl_context(config))
	opener = urllib.request.build_opener(handler)
	rest_request = urllib.request.Request(url=url, data=str.encode(json_string))

	rest_request.add_header('Content-Type', 'application/json')
	rest_request.add_header('Accept', 'application/json')

	b64 = base64.b64encode(
		(config['nodename'] + ':' + config['password']).encode()).decode()
	rest_request.add_header('Authorization', 'Basic ' + b64)
	rest_response = opener.open(rest_request)
	response = rest_response.read().decode()
	# print('  response=' + response)
	return json.loads(response)


def pxgrid_service_lookup(config, service_name):
	url = 'https://{}:8910/pxgrid/control/ServiceLookup'.format(config['hostname'])
	payload = {'name': service_name}

	json_string = json.dumps(payload)
	# print("pxgrid url=" + url)
	# print('  request=' + json_string)

	handler = urllib.request.HTTPSHandler(context=get_ssl_context(config))
	opener = urllib.request.build_opener(handler)
	rest_request = urllib.request.Request(url=url, data=str.encode(json_string))

	rest_request.add_header('Content-Type', 'application/json')
	rest_request.add_header('Accept', 'application/json')

	b64 = base64.b64encode(
        (config['nodename'] + ':' + config['password']).encode()).decode()
	rest_request.add_header('Authorization', 'Basic ' + b64)
	rest_response = opener.open(rest_request)
	response = rest_response.read().decode()
	# print('  response=' + response)
	return json.loads(response)


def pxgrid_anc_policies(config):
	url = 'https://{}:8910/pxgrid/ise/config/anc/getPolicies'.format(config['hostname'])
	payload = {}

	json_string = json.dumps(payload)
	# print("pxgrid url=" + url)
	# print('  request=' + json_string)

	handler = urllib.request.HTTPSHandler(context=get_ssl_context(config))
	opener = urllib.request.build_opener(handler)
	rest_request = urllib.request.Request(url=url, data=str.encode(json_string))

	rest_request.add_header('Content-Type', 'application/json')
	rest_request.add_header('Accept', 'application/json')

	b64 = base64.b64encode(
        (config['nodename'] + ':' + config['secret']).encode()).decode()
	rest_request.add_header('Authorization', 'Basic ' + b64)
	rest_response = opener.open(rest_request)
	response = rest_response.read().decode()
	# print('  response=' + response)
	return json.loads(response)


def pxgrid_anc_endpoints(config):
	url = 'https://{}:8910/pxgrid/ise/config/anc/getEndpoints'.format(config['hostname'])
	payload = {}

	json_string = json.dumps(payload)
	# print("pxgrid url=" + url)
	# print('  request=' + json_string)

	handler = urllib.request.HTTPSHandler(context=get_ssl_context(config))
	opener = urllib.request.build_opener(handler)
	rest_request = urllib.request.Request(url=url, data=str.encode(json_string))

	rest_request.add_header('Content-Type', 'application/json')
	rest_request.add_header('Accept', 'application/json')

	b64 = base64.b64encode(
		(config['nodename'] + ':' + config['secret']).encode()).decode()
	rest_request.add_header('Authorization', 'Basic ' + b64)
	rest_response = opener.open(rest_request)
	response = rest_response.read().decode()
	# print('  response=' + response)
	return json.loads(response)


def pxgrid_anc_apply_policy_to_Ip(config, ipAddress, policyName):
	url = 'https://{}:8910/pxgrid/ise/config/anc/applyEndpointByIpAddress'.format(config['hostname'])
	payload = {
		"policyName": policyName,
		"ipAddress": ipAddress
	}

	json_string = json.dumps(payload)
	print("pxgrid url=" + url)
	print('  request=' + json_string)

	handler = urllib.request.HTTPSHandler(context=get_ssl_context(config))
	opener = urllib.request.build_opener(handler)
	rest_request = urllib.request.Request(url=url, data=str.encode(json_string))

	rest_request.add_header('Content-Type', 'application/json')
	rest_request.add_header('Accept', 'application/json')

	b64 = base64.b64encode(
		(config['nodename'] + ':' + config['secret']).encode()).decode()
	rest_request.add_header('Authorization', 'Basic ' + b64)
	rest_response = opener.open(rest_request)
	response = rest_response.read().decode()
	print('  response=' + response)
	return json.loads(response)


def pxgrid_anc_clear_policy_from_Endpoint(config, macAddress):
	url = 'https://{}:8910/pxgrid/ise/config/anc/clearEndpointByMacAddress'.format(config['hostname'])
	payload = {
		"macAddress": macAddress
	}

	json_string = json.dumps(payload)
	print("pxgrid url=" + url)
	print('  request=' + json_string)

	handler = urllib.request.HTTPSHandler(context=get_ssl_context(config))
	opener = urllib.request.build_opener(handler)
	rest_request = urllib.request.Request(url=url, data=str.encode(json_string))

	rest_request.add_header('Content-Type', 'application/json')
	rest_request.add_header('Accept', 'application/json')

	b64 = base64.b64encode(
		(config['nodename'] + ':' + config['secret']).encode()).decode()
	rest_request.add_header('Authorization', 'Basic ' + b64)
	rest_response = opener.open(rest_request)
	response = rest_response.read().decode()
	print('  response=' + response)
	return json.loads(response)


def pxgrid_Get_Sessions(config):
	url = 'https://{}:8910/pxgrid/mnt/sd/getSessions'.format(config['hostname'])
	payload = {}

	json_string = json.dumps(payload)
	# print("pxgrid url=" + url)
	# print('  request=' + json_string)

	handler = urllib.request.HTTPSHandler(context=get_ssl_context(config))
	opener = urllib.request.build_opener(handler)
	rest_request = urllib.request.Request(url=url, data=str.encode(json_string))

	rest_request.add_header('Content-Type', 'application/json')
	rest_request.add_header('Accept', 'application/json')

	b64 = base64.b64encode(
		(config['nodename'] + ':' + config['sessionSecret']).encode()).decode()
	rest_request.add_header('Authorization', 'Basic ' + b64)
	rest_response = opener.open(rest_request)
	response = rest_response.read().decode()
	# print('  response=' + response)
	return json.loads(response)


def get_All_Endpoints(config):
	"""

	:return:
	"""
	url = 'https://{}:9060/ers/config/endpoint'.format(config['hostname'])
	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json'
	}
	body = {}
	response = requests.request('GET', url, headers=headers, data=body, auth=HTTPBasicAuth('Admin', 'C1sco12345'), verify=False)
	result = response.json()
	return result['SearchResult']['resources']
