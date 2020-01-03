from core.sast.constants import Constants
from elasticsearch import Elasticsearch
import json
from config.config import Config


class elastic():
	"""
	"""
	def __init__(self):
		self.config = Config()
		self.es = Elasticsearch([self.config.PATRONUS_ES_URL])
		self.es.indices.create(index="patronus", ignore=400)

	def push_data_to_elastic_search(self, data:str):
		return self.es.index(index="patronus", body=json.dumps(data))
		
