"""Passive subject/body-only structure features for versioned email experiments."""
import re
import numpy as np
from scipy.sparse import csr_matrix
from sklearn.base import BaseEstimator,TransformerMixin
from .ml_features import normalize_email_text

PIPELINE_VERSION='email-multiscale-v3'

class TextStructureTransformer(BaseEstimator,TransformerMixin):
    names=['log_chars','log_words','url_per_word','digit_fraction','punctuation_fraction','nonascii_fraction','money_per_word','mean_word_length','unique_word_fraction','exclamation_per_word','question_per_word','account_per_word']
    def fit(self,X,y=None):return self
    def transform(self,X):
        rows=[]
        for raw in X:
            text=normalize_email_text(str(raw));words=re.findall(r'\w+',text);n=max(len(words),1);chars=max(len(text),1)
            rows.append([np.log1p(len(text)),np.log1p(len(words)),len(re.findall(r'https?://',text))/n,sum(c.isdigit() for c in text)/chars,sum(not c.isalnum() and not c.isspace() for c in text)/chars,sum(ord(c)>127 for c in text)/chars,len(re.findall(r'[$£€]|\b(?:payment|invoice|bank)\b',text))/n,sum(map(len,words))/n,len(set(words))/n,text.count('!')/n,text.count('?')/n,len(re.findall(r'\b(?:account|password|login|verify)\b',text))/n])
        return csr_matrix(np.asarray(rows,dtype=float))
    def get_feature_names_out(self,input_features=None):return np.asarray(self.names,dtype=object)
