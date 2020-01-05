from core.sast.constants import Constants
from core.utils.elastic import elastic
from mysql.connector import errorcode
from core.utils.utils import Utils
from mysql.connector import Error
import mysql.connector
import configparser
import requests
import hashlib
import json
import uuid
import time
import os
import sys
from config.config import Config

class Fsbparser():
	def __init__(self):
		self.es = elastic()
		self.const = Constants()
		self.utils = Utils()
		self.config = Config()

	def gradle_output(self, repo:str):
			if os.path.exists('%s%s/build/reports/findbugs/main.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)):
				with open('%s%s/build/reports/findbugs/main.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)) as file:
					res = json.loads(file.read())
					if "BugInstance" in res['BugCollection']:
						for i in res['BugCollection']['BugInstance']:
							issue = {'repo':repo, 'scanner': 'find-sec-bugs', 'bug_type':'','language': 'java', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
							try:
								if i['@category'] == "SECURITY":
									issue['bug_type'] = i['@type']
									issue['class_name'] = i['Class']['@classname']
									if "Method" in i:
										issue["method_name"] = i['Method']['@name']
									if type(i['SourceLine']) == list:
										issue["line_no_start"] = i['SourceLine'][0]['@start']
										issue["line_no_end"] = i['SourceLine'][0]['@start']
									if type(i['SourceLine']) == dict:
										issue["line_no_start"] = i['SourceLine']['@start']
										issue["line_no_end"] = i['SourceLine']['@start']
									if self.utils.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
										self.utils.sent_result_to_db(repo, str(issue), 'java', 'find-sec-bugs')
										self.es.push_data_to_elastic_search(issue, repo)
										# self.utils.sent_to_slack(repo, json.dumps(issue, indent=4))
							except Exception as e:
								print(e)

			if os.path.exists('%s%s/main.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)):
				with open('%s%s/main.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)) as file:
					res = json.loads(file.read())
					if "BugInstance" in res['BugCollection']:
						for i in res['BugCollection']['BugInstance']:
							issue = {'repo':repo, 'scanner': 'find-sec-bugs', 'bug_type':'','language': 'java', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
							try:
								if i['@category'] == "SECURITY":
									issue['bug_type'] = i['@type']
									issue['class_name'] = i['Class']['@classname']
									if "Method" in i:
										issue["method_name"] = i['Method']['@name']
									if type(i['SourceLine']) == list:
										issue["line_no_start"] = i['SourceLine'][0]['@start']
										issue["line_no_end"] = i['SourceLine'][0]['@start']
									if type(i['SourceLine']) == dict:
										issue["line_no_start"] = i['SourceLine']['@start']
										issue["line_no_end"] = i['SourceLine']['@start']
									if self.utils.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
										self.utils.sent_result_to_db(repo, str(issue), 'java', 'find-sec-bugs')
										self.es.push_data_to_elastic_search(issue, repo)
										# self.utils.sent_to_slack(repo, json.dumps(issue, indent=4))
							except Exception as e:
								print(e)			
			return

	def maven_output(self, repo:str):
		if os.path.exists('%s%s/target/spotbugsXml.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)):
			with open('%s%s/target/spotbugsXml.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)) as file:
				res = json.loads(file.read())
				if "BugInstance" in res['aBugCollection']:
					for i in res['BugCollection']['BugInstance']:
						issue = {'repo':repo, 'scanner': 'find-sec-bugs', 'bug_type':'','language': 'java', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
						try:
							if type(i) is dict:
								if i['@category'] == "SECURITY":
									issue["issue"] = i['@type']
									result["class_name"] = i['Class']['@classname']
									issue["method_name"] = i['Method']['@name']
									if type(i['SourceLine']) == list:
										issue["line_no_start"] = i['SourceLine'][0]['@start'] 
										issue["line_no_end"] + i['SourceLine'][0]['@start']
									if type(i['SourceLine']) == dict:
										issue["line_no_end"] = i['SourceLine']['@start']
										issue["line_no_end"] = i['SourceLine']['@start']
									if self.utils.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
										self.utils.sent_result_to_db(repo, str(issue), 'java', 'find-sec-bugs')
										self.es.push_data_to_elastic_search(issue, repo)
										self.utils.sent_to_slack(repo, json.dumps(issue, indent=4))
						except Exception as e:
							print(e)

		if os.path.exists('%s%s/spotbugsXml.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)):
			with open('%s%s/spotbugsXml.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)) as file:
				res = json.loads(file.read())
				if "BugInstance" in res['aBugCollection']:
					for i in res['BugCollection']['BugInstance']:
						issue = {'repo':repo, 'scanner': 'find-sec-bugs', 'bug_type':'','language': 'java', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
						try:
							if type(i) is dict:
								if i['@category'] == "SECURITY":
									issue["issue"] = i['@type']
									result["class_name"] = i['Class']['@classname']
									issue["method_name"] = i['Method']['@name']
									if type(i['SourceLine']) == list:
										issue["line_no_start"] = i['SourceLine'][0]['@start'] 
										issue["line_no_end"] + i['SourceLine'][0]['@start']
									if type(i['SourceLine']) == dict:
										issue["line_no_end"] = i['SourceLine']['@start']
										issue["line_no_end"] = i['SourceLine']['@start']
									if self.utils.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
										self.utils.sent_result_to_db(repo, str(issue), 'java', 'find-sec-bugs')
										self.es.push_data_to_elastic_search(issue, repo)
										self.utils.sent_to_slack(repo, json.dumps(issue, indent=4))
						except Exception as e:
							print(e)			
		return