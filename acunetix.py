#!/usr/bin/python3

### Example of usage:
###
### Remove targets "python3 acunetix.py -rmrf"
### Add targets and create group "python3 acunetix.py -f targets_file.txt -g group_name
### Add targets and select speed (moderate / slow / sequential) "python3 acunetix.py -f targets.txt -d slow"

import requests
import json
import sys
import time
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

API_KEY = '..............'
SCANNER_URL = 'https://127.0.0.1:3443'
PROFILE_ID = '11111111-1111-1111-1111-111111111111' # you can change to custom if you want, else 'Full Scan'



class AcunetixManager(object):
	API_KEY = ''
	SCANNER_URL = ''
	N = 499 # acunetix doesn't allow to add more for one time now
	full_scan_profile_id = '11111111-1111-1111-1111-111111111111'
	headers = {}
	sended_targets_counter = 0
	decreased_speed_targets_counter = 0
	number_targets = 0

	def __init__(self, API_KEY, SCANNER_URL):
		self.API_KEY = API_KEY
		self.SCANNER_URL = SCANNER_URL
		self.headers = {
			'Content-type': 'application/json',
			'Accept': 'text/plain',
			'X-Auth': API_KEY
			}


	def remove_all_targets(self):
		counter_removed_targets = 0
		current_avaliable_targets = -1
		while current_avaliable_targets != 0:
			response = requests.get(
				'%s/api/v1/targets?l=100' % self.SCANNER_URL,
				headers=self.headers,
				verify=False)
			if response.status_code == 200:
				current_avaliable_targets = len(json.loads(response.text)['targets'])
			else:
				print(response.text)
				print('Something wrong. fail getting targets')
				exit()
			target_id_list = [target['target_id'] for target in json.loads(response.text)['targets']]
			# print(target_id_list)
			response = requests.post(
				'%s/api/v1/targets/delete' % self.SCANNER_URL,
				headers=self.headers,
				verify=False,
				data=json.dumps({"target_id_list":target_id_list}))
			if response.status_code == 204:
				counter_removed_targets += 100
				print("success removed",counter_removed_targets)
			else:
				print('Something wrong. fail removing targets')
				print(response.text)
				exit()

	def add_targets_to_scanner(self, targets, group_id=None):
		if group_id is None:
			response = requests.post(
				'%s/api/v1/targets/add' % self.SCANNER_URL,
				headers=self.headers,
				verify=False,
				data=json.dumps({'targets':[{"address":host,"description":""} for host in targets],"groups":[]}))
		else:
			response = requests.post(
				'%s/api/v1/targets/add' % self.SCANNER_URL,
				headers=self.headers,
				verify=False,
				data=json.dumps({'targets':[{"address":host,"description":""} for host in targets],"groups":[group_id]}))

		if response.status_code == 200:
			print("Success adding targets")
		else:
			print(response.text)
			print('Something wrong. fail adding')
			exit()
		list_target_id = [target_info['target_id'] for target_info in json.loads(response.text)['targets']]
		return list_target_id

	def run_scanner(self, targets_filename, profile_id = full_scan_profile_id, group_name=None, scan_speed=None): # by default 'Full Scan'
		if group_name is not None:
			group_id = self.create_group(group_name)
		else:
			group_id = None

		with open(targets_filename) as file:
			hosts = [line.rstrip('\n') for line in file]
		self.number_targets = len(hosts)
		for chunk in self.chunks(hosts, self.N):
			list_target_id = self.add_targets_to_scanner(chunk, group_id=group_id)
			if scan_speed != None:
				self.change_scan_speed(list_target_id, scan_speed)
			self.send_to_scan(list_target_id, profile_id)
		self.sended_targets_counter = 0
		self.decreased_speed_targets_counter = 0

	def change_scan_speed(self, list_target_id, speed_mode):
		for target_id in list_target_id:
			self.decreased_speed_targets_counter+=1
			response = requests.patch(
				'%s/api/v1/targets/%s/configuration' % (self.SCANNER_URL, target_id),
				headers=self.headers,
				verify=False,
				timeout=None,
				data=json.dumps({"scan_speed":speed_mode,"login":{"kind":"none"},"ssh_credentials":{"kind":"none"},"sensor":False,"user_agent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21","case_sensitive":"auto","limit_crawler_scope":True,"excluded_paths":[],"authentication":{"enabled":False},"proxy":{"enabled":False},"technologies":[],"custom_headers":[],"custom_cookies":[],"debug":False,"client_certificate_password":"","client_certificate_url":None,"issue_tracker_id":"","excluded_hours_id":""})
				)
			if response.status_code == 204:
				print("Success configurated %d/%d" % (self.decreased_speed_targets_counter,self.number_targets))
			else:
				print(response.text)
				print(target_id,"fail config")
				exit()

	def send_to_scan(self, list_target_id, profile_id):
		for target_id in list_target_id:
			self.sended_targets_counter+=1
			response = requests.post(
				'%s/api/v1/scans' % self.SCANNER_URL,
				headers=self.headers,
				verify=False,
				timeout=None,
				data=json.dumps({"profile_id":profile_id,"incremental":False,"schedule":{"disable":False,"start_date":None,"time_sensitive":False},"target_id":target_id}))
			if response.status_code == 201:
				print("Success send to scan %d/%d" % (self.sended_targets_counter,self.number_targets))
			else:
				print(response.text)
				print('Something wrong. fail send to scan')
				exit()

	def chunks(self,lst, n):
	    return [lst[i:i + n] for i in range(0, len(lst), n)]
	
	def get_group_id(self, group_name):
		response = requests.get(
			'%s/api/v1/target_groups?l=100' % self.SCANNER_URL,
			headers=self.headers,
			verify=False)
		if response.status_code == 200:
			for group in json.loads(response.text)['groups']:
				if group_name == group['name']:
					return group['group_id']

	def create_group(self, group_name):
		response = requests.post(
			'%s/api/v1/target_groups' % self.SCANNER_URL,
			headers=self.headers,
			verify=False,
			data=json.dumps({"name":group_name,"description":""}))
		if response.status_code == 201:
			print(group_name+' group successfuly created')
			group_id = json.loads(response.text)['group_id']
		elif response.status_code == 409 and json.loads(response.text)['message']=="Group name should be unique":
			print(group_name+' already exists')
			return self.get_group_id(group_name)
		else:
			print(response.text)
			print('Something wrong. fail creating group')
			exit()
		return group_id
		

def main():
	if sys.version_info[0] < 3:
		raise Exception("Python 3 or a more recent version is required.")
	parser = argparse.ArgumentParser(description='Acunetix helpful script')
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-rmrf",
		help="removing all targets",
		action='store_true')
	group.add_argument("-f", "--file",
		dest="filename",
		help="file which contains list of urls/domans", 
		metavar="FILE",
		)
	parser.add_argument("-g", "--group",
		dest="group_name",
		default=None,
		help="if group doesn't exist it will be created. All hosts will be added to this group")
	parser.add_argument("-d", "--decrease",
		dest="speed_decrease",
		help="decrease scan speed",
		default=None,
		choices=['moderate', 'slow', 'sequential'])
	args = parser.parse_args()

	acu = AcunetixManager(API_KEY, SCANNER_URL)
	if args.rmrf:
		acu.remove_all_targets()
	elif args.filename:
		acu.run_scanner(args.filename, profile_id=PROFILE_ID, group_name=args.group_name,scan_speed=args.speed_decrease)


if __name__ == "__main__":
    main()
