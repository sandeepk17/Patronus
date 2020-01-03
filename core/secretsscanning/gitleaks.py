from core.utils.utils import Utils
from config.config import Config
import os

class Gitleaks():
    """
    """

    def __init__(self):
        self.utils = Utils()
        self.config = Config()
        
    def gitleaks_scan(self, repo: str):
    	os.chdir('%s' % (self.config.PATRONUS_DOWNLOAD_LOCATION))
    	self.utils.execute_cmd("gitleaks -r %s --report=%s/gitleaks.json --report-format=json" % (repo, repo),repo)
    	return