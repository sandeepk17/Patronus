from core.sast.constants import Constants
from core.utils.utils import Utils
from core.sast.java import Java
from os.path import dirname
import subprocess
import logging
import os
from config.config import Config

class DependencyCheck():
	"""
	"""

	def __init__(self):
		self.java = Java()
		self.const = Constants()
		self.utils = Utils()
		self.config = Config()

	def dependency_check(self, repo: str):
		parent_dir = dirname(dirname(os.path.abspath(os.path.dirname(__file__))))
		os.chdir(parent_dir + "/tools/dependency-check/bin/")
		try:
			self.utils.execute_cmd("./dependency-check.sh --scan %s%s -f JSON -o %s%s" % (self.config.PATRONUS_DOWNLOAD_LOCATION,repo, self.config.PATRONUS_DOWNLOAD_LOCATION,repo), repo)
			logging.info("Successfully ran dependency-check on repo %s" % (repo))
		except:
			logging.debug("Error running dependency-check on repo %s" % (repo))
		return

	def dependency_check_maven(self, repo:str):
		try:
			os.chdir("%s/%s" % (self.config.PATRONUS_DOWNLOAD_LOCATION,repo))
			self.utils.execute_cmd("mvn compile", repo)
			self.utils.execute_cmd("mvn dependency-check:check", repo)
			logging.info("Successfully ran dependency-check on repo %s" % (repo))
		except:
			logging.debug("Error running dependency-check on repo %s" (repo))
		return

	def dependency_check_gradle(self, repo:str):
		try:
			os.chdir("%s/%s" % (self.config.PATRONUS_DOWNLOAD_LOCATION, repo))
			self.utils.execute_cmd("./gradlew dependencyCheckAnalyze", repo)
			logging.info("Successfully ran dependency-check on repo %s" % (repo))
		except:
			logging.debug("Error running dependency-check on repo %s" (repo), repo)
		return