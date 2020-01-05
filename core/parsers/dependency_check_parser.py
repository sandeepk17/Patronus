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
import os
import sys

class Dependencycheckparser():
	def __init__(self):
		self.es = elastic()
		self.utils = Utils()
		self.config = Config()

	def dependency_check_results_gradle(self, repo:str):
			if os.path.exists('%s%s/build/reports/dependency-check-report.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)):
				with open('%s%s/build/reports/dependency-check-report.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)) as file:
					res = json.loads(file.read())
					for i in res['dependencies']:
						issue = {'repo':repo, 'scanner': 'dependency-check', 'bug_type':'','language': 'java', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
						if i.get('vulnerabilities'):
							for j in i['vulnerabilities']:
								if j['severity'] == "HIGH" or j['severity'] == "CRITICAL":
									issue["dependency_url"] = i['packages'][0]['url']
									issue["CVE"] = j['name']
									issue["description"] = j['description']
									issue["source_url"] = j['references'][0]['url']
									logging.info("return of check_issue_exits for project %s : %s" % (repo, check_issue_exits(repo, str(issue))))
									if self.utils.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
										self.utils.sent_result_to_db(repo, str(issue), 'java', 'dependency-check')
										self.es.push_data_to_elastic_search(issue, repo)
										self.utils.sent_to_slack(repo, json.dumps(issue, indent=4))

			if os.path.exists('%s%s/dependency-check-report.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)):
				with open('%s%s/dependency-check-report.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)) as file:
					res = json.loads(file.read())
					for i in res['dependencies']:
						issue = {'repo':repo, 'scanner': 'dependency-check', 'bug_type':'','language': 'java', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
						if i.get('vulnerabilities'):
							for j in i['vulnerabilities']:
								if j['severity'] == "HIGH" or j['severity'] == "CRITICAL":
									issue["dependency_url"] = i['packages'][0]['url']
									issue["CVE"] = j['name']
									issue["description"] = j['description']
									issue["source_url"] = j['references'][0]['url']
									logging.info("return of check_issue_exits for project %s : %s" % (repo, check_issue_exits(repo, str(issue))))
									if self.utils.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
										self.utils.sent_result_to_db(repo, str(issue), 'java', 'dependency-check')
										self.es.push_data_to_elastic_search(issue, repo)
										self.utils.sent_to_slack(repo, json.dumps(issue, indent=4))		
			return
			
	def dependency_check_results_maven(self, repo:str):
		result = ""
		if os.path.exists('%s%s/target/dependency-check-report.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)):
			with open('%s%s/target/dependency-check-report.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)) as file:
				res = json.loads(file.read())
				for i in res['dependencies']:
					issue = {'repo':repo, 'scanner': 'dependency-check', 'bug_type':'','language': 'java', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
					if i.get('vulnerabilities'):
						for j in i['vulnerabilities']:
							if j['severity'] == "HIGH" or j['severity'] == "CRITICAL":
								issue["dependency_url"] = i['packages'][0]['url']
								issue["CVE"] = j['name']
								issue["description"] = j['description']
								issue["source_url"] = j['references'][0]['url']
								logging.info("return of check_issue_exits for project %s : %s" % (repo, check_issue_exits(repo, str(issue))))
								if self.utils.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
									self.utils.sent_result_to_db(repo, str(issue), 'java', 'dependency-check')
									self.es.push_data_to_elastic_search(issue, repo)
									self.utils.sent_to_slack(repo, json.dumps(issue, indent=4))

		if os.path.exists('%s%s/dependency-check-report.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)):
			with open('%s%s/dependency-check-report.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)) as file:
				res = json.loads(file.read())
				for i in res['dependencies']:
					issue = {'repo':repo, 'scanner': 'dependency-check', 'bug_type':'','language': 'java', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
					if i.get('vulnerabilities'):
						for j in i['vulnerabilities']:
							if j['severity'] == "HIGH" or j['severity'] == "CRITICAL":
								issue["dependency_url"] = i['packages'][0]['url']
								issue["CVE"] = j['name']
								issue["description"] = j['description']
								issue["source_url"] = j['references'][0]['url']
								logging.info("return of check_issue_exits for project %s : %s" % (repo, check_issue_exits(repo, str(issue))))
								if self.utils.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
									self.utils.sent_result_to_db(repo, str(issue), 'java', 'dependency-check')
									self.es.push_data_to_elastic_search(issue, repo)
									self.utils.sent_to_slack(repo, json.dumps(issue, indent=4))		
		return

	def node_results(self, repo:str):
		result = ""
		if os.path.exists('%s%s/dependency-check-report.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)):
			with open('%s%s/dependency-check-report.json' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)) as file:
				res = json.loads(file.read())
				for i in res['dependencies']:
					issue = {'repo':repo, 'scanner': 'dependency-check', 'bug_type':'','language': 'node-js', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
					if i.get('vulnerabilities'):
						for j in i['vulnerabilities']:
							if j['severity'] == "HIGH" or j['severity'] == "CRITICAL":
								issue["dependency_url"] = i['packages'][0]['url']
								issue["CVE"] = j['name']
								issue["description"] = j['description']
								issue["source_url"] = j['references'][0]['url']
								logging.info("return of check_issue_exits for project %s : %s" % (repo, check_issue_exits(repo, str(issue))))
								if self.utils.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
									self.utils.sent_result_to_db(repo, str(issue), 'java', 'dependency-check')
									self.es.push_data_to_elastic_search(issue, repo)
									self.utils.sent_to_slack(repo, json.dumps(issue, indent=4))		
		return