from core.sast.constants import Constants
from core.utils.elastic import elastic
from mysql.connector import errorcode
from mysql.connector import Error
import mysql.connector
import configparser
import requests
import hashlib
import json
import uuid
import time
import os
import hashlib
import sys
from config.config import Config

class Jsonparsing():
	def __init__(self):
		self.es = elastic()
		self.const = Constants()
		self.config = Config()

	def gradle_output(self, repo:str):
		if os.path.exists('%s%s/build/reports/findbugs/main.json' % (self.const.DOWNLOAD_LOCATION, repo)):
			with open('%s%s/build/reports/findbugs/main.json' % (self.const.DOWNLOAD_LOCATION, repo)) as file:
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
								if self.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
									self.sent_result_to_db(repo, str(issue))
									self.es.push_data_to_elastic_search(issue)
									self.sent_to_slack(repo, json.dumps(issue, indent=4))
						except Exception as e:
							print(e)			
		return

	def maven_output(self, repo:str):
		if os.path.exists('%s%s/target/spotbugsXml.json' % (self.const.DOWNLOAD_LOCATION, repo)):
			with open('%s%s/target/spotbugsXml.json' % (self.const.DOWNLOAD_LOCATION, repo)) as file:
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
									if self.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
										self.sent_result_to_db(repo, str(issue))
										self.es.push_data_to_elastic_search(issue)
										self.sent_to_slack(repo, json.dumps(issue, indent=4))
						except Exception as e:
							print(e)			
		return

	def golang_output(self, repo:str):
		if os.path.exists('%s%s/results.json' % (self.const.DOWNLOAD_LOCATION, repo)):
			with open('%s%s/results.json' % (self.const.DOWNLOAD_LOCATION, repo)) as file:
				res = json.loads(file.read())
				for i in res['Issues']:
					issue = {'repo':repo, 'scanner': 'gosec', 'bug_type':'','language': 'golang', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
					# if i['severity'] == "HIGH":
					issue["issue"] = i['details']
					issue["file_name"] = i['file']
					issue["vulnerable_code"] = i['code']
					issue["line_no"] = i['line']
					if self.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
						self.sent_result_to_db(repo, str(issue))
						self.es.push_data_to_elastic_search(issue)
						self.sent_to_slack(repo, json.dumps(issue, indent=4))		
		return

	def node_output(self, repo:str):
		if os.path.exists('%s%s/node_results.json' % (self.const.DOWNLOAD_LOCATION, repo)):
			with open('%s%s/node_results.json' % (self.const.DOWNLOAD_LOCATION, repo)) as file:
				res = json.loads(file.read())
				if self.es.get('advisories'):
					for i in res['advisories']:
						issue = {'repo':repo, 'scanner': 'npm-audit', 'bug_type':'','language': 'nodejs', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
						# if res['advisories'][i]['severity'] ==  "high":
						issue["module_name"] = res['advisories'][i]['module_name']
						issue["title"] = res['advisories'][i]['title']
						issue["severity"] = res['advisories'][i]['severity']
						issue["advisories_url"] = res['advisories'][i]['url']
						issue["vulnerable_versions"] = res['advisories'][i]['vulnerable_versions']
						issue["patched_versions"] = res['advisories'][i]['patched_versions']
						if self.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
							self.sent_result_to_db(repo, str(issue))
							self.es.push_data_to_elastic_search(issue)
							self.sent_to_slack(repo, json.dumps(issue, indent=4))		
		return

	def dependency_check_results_gradle(self, repo:str):
		if os.path.exists('%s%s/build/reports/dependency-check-report.json' % (self.const.DOWNLOAD_LOCATION, repo)):
			with open('%s%s/build/reports/dependency-check-report.json' % (self.const.DOWNLOAD_LOCATION, repo)) as file:
				res = json.loads(file.read())
				for i in res['dependencies']:
					issue = {'repo':repo, 'scanner': 'dependency-check', 'bug_type':'','language': 'dep-check', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
					if i.get('vulnerabilities'):
						for j in i['vulnerabilities']:
							if j['severity'] == "HIGH" or j['severity'] == "CRITICAL":
								issue["dependency_url"] = i['packages'][0]['url']
								issue["CVE"] = j['name']
								issue["description"] = j['description']
								issue["source_url"] = j['references'][0]['url']
								if self.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
									self.sent_result_to_db(repo, str(issue))
									self.es.push_data_to_elastic_search(issue)
									self.sent_to_slack(repo, json.dumps(issue, indent=4))		
		return
		
	def dependency_check_results_maven(self, repo:str):
		result = ""
		if os.path.exists('%s%s/target/dependency-check-report.json' % (self.const.DOWNLOAD_LOCATION, repo)):
			with open('%s%s/target/dependency-check-report.json' % (self.const.DOWNLOAD_LOCATION, repo)) as file:
				res = json.loads(file.read())
				for i in res['dependencies']:
					issue = {'repo':repo, 'scanner': 'dependency-check', 'bug_type':'','language': 'dep-check', 'class_name':'', 'method_name':'', 'line_no_start':'', 'line_no_end':'','file_name': '', 'vulnerable_code':'', 'severity':'', 'module_name':'', 'advisories_url':'', 'vulnerable_versions':'', 'patched_versions':'', 'dependency_url':'', 'CVE':'', 'description':'', 'source_url':'', 'title':''}
					if i.get('vulnerabilities'):
						for j in i['vulnerabilities']:
							if j['severity'] == "HIGH" or j['severity'] == "CRITICAL":
								issue["dependency_url"] = i['packages'][0]['url']
								issue["CVE"] = j['name']
								issue["description"] = j['description']
								issue["source_url"] = j['references'][0]['url']
								if self.check_issue_exits(repo, str(issue)) == False and str(issue) != "":
									self.sent_result_to_db(repo, str(issue))
									self.es.push_data_to_elastic_search(issue)
									self.sent_to_slack(repo, json.dumps(issue, indent=4))		
		return

	def sent_result_to_db(self,repo:str, text:str, language:str=None):
		try:
			connection = self.mysql_connection()
			sql_insert_query = "INSERT INTO results (scan_id, project_name, issue, language, hash) VALUES (%s, %s, %s, %s, %s)"
			sid = uuid.uuid1()
			res_hash = hashlib.sha256(text.encode()).hexdigest()
			val = (str(sid), repo, text, language, res_hash)
			cursor = connection.cursor(prepared=True)
			result = cursor.execute(sql_insert_query, val)
			connection.commit()
		except mysql.connector.Error as error:
			print(error)
			connection.rollback()
		finally:
		    if(connection.is_connected()):
		        cursor.close()
		        connection.close()
		return

	def mysql_connection(self):
		# path = os.path.dirname(os.path.abspath(__file__))
		# config = configparser.ConfigParser()
		# config_file = os.path.join(os.path.dirname(__file__) + '/../../config')
		# config.read(config_file)
		# config.sections()
		# connection = mysql.connector.connect(host=config['DB']['host'], database=config['DB']['database'], user=config['DB']['user'], password=config['DB']['password'])
		connection = mysql.connector.connect(host=self.config.DB_HOST, database=self.config.DB_DATABASE, user=self.config.DB_USER, password=self.config.DB_PASSWORD)
		return connection

	def check_issue_exits(self, repo:str, text:str):
		issues_list = []
		try:
		    connection = self.mysql_connection()
		    sql_select_query = "SELECT hash from results WHERE project_name=%s"
		    res_hash = hashlib.sha256(text.encode()).hexdigest()
		    val = (repo,)
		    cursor = connection.cursor(prepared=True)
		    result = cursor.execute(sql_select_query, val)
		    res = cursor.fetchall()
		    for x in res:
		    	issues_list.append(x[0].decode())
		    if res_hash in issues_list:
		    	return True
		except mysql.connector.Error as error:
			print(error)
		finally:
			if (connection.is_connected()):
				cursor.close()
				connection.close()
		return False

	def sent_to_slack(self, repo:str, data:str):
		url = self.config.SLACK_WEB_HOOK_URL
		text = "Results for %s \n``` %s ```" % (repo, data)
		payload = {'text': text}
		requests.post(url, data=json.dumps(payload))