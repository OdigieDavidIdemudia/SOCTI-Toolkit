"""
SepRep v0.3 - Reputation Engine Module
"""
import os
import re
import time
import requests
import logging
import urllib.parse
import urllib3
import json

# Suppress SSL warnings for proxy usage
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SepRepConfig:
    VERSION = "0.3"
    TIMEOUT = 10
    RATE_LIMIT_SAFE = True
    SEQUENTIAL_PROCESSING = True

    @staticmethod
    def get_headers(api_key):
        return {
            "x-apikey": api_key,
            "Accept": "application/json"
        }

class Indicator:
    TYPE_IPV4 = "ipv4"
    TYPE_MD5 = "md5"
    TYPE_SHA1 = "sha1"
    TYPE_SHA256 = "sha256"
    TYPE_DOMAIN = "domain"
    TYPE_UNKNOWN = "unknown"

    @staticmethod
    def classify(text):
        text = text.strip()
        
        # Order of evaluation: ipv4, sha256, sha1, md5, domain
        
        # IPv4
        # Basic regex, not strict 0-255 validation but good enough for classification
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', text):
            return Indicator.TYPE_IPV4
            
        # SHA256 (64 hex chars)
        if re.match(r'^[a-fA-F0-9]{64}$', text):
            return Indicator.TYPE_SHA256
            
        # SHA1 (40 hex chars)
        if re.match(r'^[a-fA-F0-9]{40}$', text):
            return Indicator.TYPE_SHA1
            
        # MD5 (32 hex chars)
        if re.match(r'^[a-fA-F0-9]{32}$', text):
            return Indicator.TYPE_MD5
            
        # Domain
        # Needs to look like a domain (dot in middle, no spaces)
        # Spec says: case_insensitive: true, regex_enforced: true
        # A simple robust domain regex:
        if re.match(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', text, re.IGNORECASE):
            return Indicator.TYPE_DOMAIN
            
        return Indicator.TYPE_UNKNOWN

class VirusTotalSource:
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key, proxy_settings=None):
        self.api_key = api_key
        self.session = requests.Session()
        self.configure_proxy(proxy_settings)
        if self.api_key:
            self.session.headers.update(SepRepConfig.get_headers(self.api_key))

    def configure_proxy(self, proxy_settings):
        if not proxy_settings or not proxy_settings.get('host'):
            return

        host = proxy_settings.get('host')
        port = proxy_settings.get('port')
        user = proxy_settings.get('username')
        pwd = proxy_settings.get('password')
        
        if user and pwd:
            user_safe = urllib.parse.quote_plus(user)
            pwd_safe = urllib.parse.quote_plus(pwd)
            proxy_url = f"http://{user_safe}:{pwd_safe}@{host}:{port}"
        else:
            proxy_url = f"http://{host}:{port}"
            
        self.session.proxies.update({
            "http": proxy_url,
            "https": proxy_url
        })
        self.session.verify = False

    def get_endpoint(self, indicator, ind_type):
        if ind_type == Indicator.TYPE_IPV4:
            return f"/ip_addresses/{indicator}"
        elif ind_type == Indicator.TYPE_DOMAIN:
            return f"/domains/{indicator}"
        elif ind_type in [Indicator.TYPE_MD5, Indicator.TYPE_SHA1, Indicator.TYPE_SHA256]:
            return f"/files/{indicator}"
        return None

    def check(self, indicator, ind_type):
        if not self.api_key:
            return self.make_result(indicator, ind_type, "Error: No API Key", 0, "Unknown")
            
        endpoint = self.get_endpoint(indicator, ind_type)
        if not endpoint:
            return self.make_result(indicator, ind_type, "Skip: Unsupported Type", 0, "Unknown")

        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            response = self.session.get(url, timeout=SepRepConfig.TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                score = stats.get('malicious', 0)
                
                # Classification Logic
                if score == 0:
                    classification = "Safe"
                elif 1 <= score <= 2:
                    classification = "Suspicious"
                elif score > 2:
                    classification = "Malicious"
                else:
                    classification = "Unknown"
                    
                return self.make_result(indicator, ind_type, None, score, classification)
                
            elif response.status_code == 404:
                return self.make_result(indicator, ind_type, None, 0, "Unknown (Not Found)")
            elif response.status_code == 429:
                 return self.make_result(indicator, ind_type, "Error: Rate Limit", 0, "Unknown")
            else:
                return self.make_result(indicator, ind_type, f"Error: HTTP {response.status_code}", 0, "Unknown")
                
        except Exception as e:
            return self.make_result(indicator, ind_type, f"Error: {str(e)}", 0, "Unknown")

    def make_result(self, indicator, ind_type, error, score, classification):
        res = {
            "indicator": indicator,
            "indicator_type": ind_type,
            "reputation_score": score,
            "classification": classification,
            "source": "VirusTotal"
        }
        if error:
            res['error'] = error
        return res

class SepRepEngine:
    def __init__(self, vt_api_key=None, proxy_settings=None):
        self.vt = VirusTotalSource(vt_api_key, proxy_settings)
        # In v0.3, only VT is supported.
        
    def process_item(self, text):
        # 1. Classification
        ind_type = Indicator.classify(text)
        
        if ind_type == Indicator.TYPE_UNKNOWN:
            return {
                "indicator": text,
                "indicator_type": "Unknown",
                "reputation_score": 0,
                "classification": "Unknown",
                "source": "Skipped",
                "error": "Invalid Format"
            }
            
        # 2. Check (VT Only in v0.3)
        return self.vt.check(text, ind_type)

