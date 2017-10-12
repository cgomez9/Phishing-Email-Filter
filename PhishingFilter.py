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
# Verbose process
verbose = True
# Classification Categories
categories = [
  'Phishing',
  'Harmless',
]