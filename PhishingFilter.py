#coding=utf-8
from __future__ import print_function

# Skit-learn
from sklearn.decomposition import TruncatedSVD
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import Normalizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import SGDClassifier
from sklearn.feature_selection import VarianceThreshold
from sklearn.metrics import classification_report
from sklearn import metrics

# For parsing HTML
import lxml.html
from ttp.ttp import Parser
from bs4 import BeautifulSoup
from urlparse import urlparse

# Utils
import numpy as np
import os
import mailbox
import sys
import re
import pickle
import base64
import json
import ast
import email.utils
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
reload(sys)
sys.setdefaultencoding('ISO-8859-2')

class PhishingFilter:
	# Verbose process
	verbose = True
	# Classification Categories
	CATEGORIES = [ 'Phishing', 'Harmless' ]

	def setVerbose(verbose):
		self.verbose = verbose

	def getVerbose():
		return verbose

	def getCategories():
		return CATEGORIES

	# Get the email body of an mbox email
	def getEmailBody(message):
		body = None
		if message.is_multipart():
			for part in message.walk():
		    	if part.is_multipart():
		        	for subpart in part.walk():
		            	if subpart.get_content_type() == 'text/plain':
		                	body = subpart.get_payload(decode=True)
		        elif part.get_content_type() == 'text/plain':
		        	body = part.get_payload(decode=True)
			elif message.get_content_type() == 'text/plain':
		    	body = message.get_payload(decode=True)}
		return body

	# Get all links from email body
	def getEmailLinks(body):
	  body_html = BeautifulSoup(body, 'html.parser', from_encoding="iso-8859-1")
	  return body_html.find_all('a')

	# Get plain text from email body
	def getEmailPlainText(body):
	  body_html = BeautifulSoup(body, 'html.parser', from_encoding="iso-8859-1")
	  return body_html.get_text()
