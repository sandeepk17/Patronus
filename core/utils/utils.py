from core.vcs.bitbucket import MyRemoteCallbacks
from core.sast.constants import Constants
from core.utils.elastic import elastic
from mysql.connector import errorcode
from mysql.connector import Error
from os.path import dirname
import mysql.connector
import configparser
import subprocess
import operator
import logging
import json
import os
import hashlib
import requests
import uuid
import time
import sys
from config.config import Config




class Utils():
	def __init__(self):
		self.const = Constants()
		self.config = Config()

	def execute_cmd(self, command, repo):
		try:
			subprocess.run(command.split())
			logging.info("Executed command ` %s on project %s`" % (command, repo))
		except Exception as e:
			logging.debug("Error while executing command on project %s ` %s `" % (command, repo))
		return

	def run_cloc(self, repo:str):
		parent_dir = dirname(dirname(os.path.abspath(os.path.dirname(__file__))))
		os.chdir(parent_dir + '/tools')
		self.execute_cmd('cloc %s%s --json --out=%s%s/cloc.txt' % (self.config.PATRONUS_DOWNLOAD_LOCATION,repo,self.config.PATRONUS_DOWNLOAD_LOCATION, repo), repo)
		return

	def parse_cloc(self, repo:str):
		lang = self.config.PATRONUS_SUPPORTED_LANG
		lang_dict = {}
		
		if os.path.exists('%s%s/cloc.txt' % (self.config.PATRONUS_DOWNLOAD_LOCATION,repo)):		
			with open('%s%s/cloc.txt' % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo)) as file:
				res = json.loads(file.read())
				if res.get('Java'):
					if res['Java']['nFiles']:
						lang_dict["java"] = res['Java']['nFiles']
				
				if res.get('JavaScript'):
					if res['JavaScript']['nFiles']:
						lang_dict["javascript"] = res['JavaScript']['nFiles']
				 
				if res.get('Go'):
					if res['Go']['nFiles']:
						lang_dict["go"] =  res['Go']['nFiles']
			return lang_dict

	def detect_programming_language(self, repo:str):
		"""
		https://stackoverflow.com/questions/268272/getting-key-with-maximum-value-in-dictionary
		"""
		self.run_cloc(repo)
		lang_dict = self.parse_cloc(repo)
		if lang_dict:
			return {'repo' : repo, 'lang' : max(lang_dict.items(), key=operator.itemgetter(1))[0]}
		return

	def sent_result_to_db(self, repo:str, text:str, language:str=None, scanner:str=None):
			try:
				connection = self.mysql_connection()
				sql_insert_query = "INSERT INTO results (scan_id, project_name, issue, language, scanner, hash) VALUES (%s, %s, %s, %s, %s, %s)"
				sid = uuid.uuid1()
				res_hash = hashlib.sha256(text.encode()).hexdigest()
				val = (str(sid), repo, text, language, scanner, res_hash)
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