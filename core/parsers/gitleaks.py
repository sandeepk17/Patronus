from core.utils.elastic import elastic
from mysql.connector import errorcode
from core.utils.utils import Utils
from mysql.connector import Error
from config.config import Config
import mysql.connector
import configparser
import requests 
import hashlib
import json
import uuid
import time
import sys
import os

class Gitleaksparser():
	def __init__(self):
		self.es = elastic()
		self.utils = Utils()
		self.config = Config()

	def gitleaks_output(self, repo:str):
			if os.path.exists('%s%s/gitleaks.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)):
				with open('%s%s/gitleaks.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)) as file:
					res = json.loads(file.read())
					for i in res['Issues']:
						issue = {'repo':repo, 'scanner': 'gosec', 'bug_type':'','language': 'golang', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
						issue["issue"] = i['details']
						issue["file_name"] = i['file']
						issue["vulnerable_code"] = i['code']
						issue["line_no"] = i['line']
						if self.utils.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
							self.utils.sent_result_to_db(repo, str(issue), 'golang', 'gosec')
							self.es.push_data_to_elastic_search(issue)
							self.utils.sent_to_slack(repo, json.dumps(issue, indent=4))		
			return