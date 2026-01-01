import os
import re
import time
import requests
import logging
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class BaseChecker:
    def __init__(self, proxy_settings=None):
        self.proxy_settings = proxy_settings
        self.session = requests.Session()
        if self.proxy_settings and self.proxy_settings.get('host'):
             self._configure_proxy()

    def _configure_proxy(self):
        p = self.proxy_settings
        host = p.get('host')
        port = p.get('port')
        user = p.get('username')
        pwd = p.get('password')
        
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
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def classify_indicator(self, indicator):
        indicator = indicator.strip()
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', indicator):
            return "ip"
        if re.match(r'^[a-fA-F0-9:]+$', indicator) and ':' in indicator:
            return "ip"
        if re.match(r'^[a-fA-F0-9]{32}$', indicator):
            return "hash"
        if re.match(r'^[a-fA-F0-9]{40}$', indicator):
            return "hash"
        if re.match(r'^[a-fA-F0-9]{64}$', indicator):
            return "hash"
        return None

class VirusTotalChecker(BaseChecker):
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key=None, proxy_settings=None):
        super().__init__(proxy_settings)
        self.api_key = api_key or os.environ.get('VT_API_KEY')
        if self.api_key:
            self.session.headers.update({"x-apikey": self.api_key})

    def check(self, indicator):
        if not self.api_key:
            return {"error": "No VT API Key"}
            
        itype = self.classify_indicator(indicator)
        if not itype:
            return {"error": "Invalid Format", "reputation": "Unknown"}
            
        endpoint = ""
        if itype == "ip":
            endpoint = f"/ip_addresses/{indicator}"
        elif itype == "hash":
            endpoint = f"/files/{indicator}"
        else:
            # VT might handle domains etc, but strict per spec
            return {"error": "Unsupported Type", "reputation": "Unknown"}
            
        url = self.BASE_URL + endpoint
        
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                
                if malicious == 0:
                    rep = "Safe"
                elif malicious <= 2:
                    rep = "Suspicious"
                else:
                    rep = "Malicious"
                    
                return {
                    "source": "VirusTotal",
                    "reputation": rep,
                    "stats": stats,
                    "malicious_score": malicious,
                    "threat_category": data.get('data', {}).get('attributes', {}).get('popular_threat_classification', {}).get('suggested_threat_label', 'Unknown')
                }
            elif response.status_code == 429:
                return {"error": "Rate Limit Exceeded", "reputation": "Unknown"}
            elif response.status_code == 404:
                return {"reputation": "Unknown (Not Found)", "stats": {}}
            else:
                return {"error": f"HTTP {response.status_code}", "reputation": "Unknown"}
        except Exception as e:
            return {"error": str(e), "reputation": "Unknown"}

class AbuseIPDBChecker(BaseChecker):
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key=None, proxy_settings=None):
        super().__init__(proxy_settings)
        self.api_key = api_key or os.environ.get('ABUSEIPDB_API_KEY')
        if self.api_key:
            self.session.headers.update({"Key": self.api_key, "Accept": "application/json"})

    def check(self, indicator):
        if not self.api_key:
            return {"error": "No AbuseIPDB API Key"}
            
        itype = self.classify_indicator(indicator)
        if itype != "ip":
            # AbuseIPDB only supports IPs
            return {"reputation": "N/A (IP Only)", "score": "N/A"}

        url = f"{self.BASE_URL}/check"
        params = {
            'ipAddress': indicator,
            'maxAgeInDays': '90',
            'verbose': 'true'
        }
        
        try:
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json().get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                
                if score == 0:
                    rep = "Safe"
                elif score <= 25:
                    rep = "Suspicious"
                else:
                    rep = "Malicious"
                    
                return {
                    "source": "AbuseIPDB",
                    "reputation": rep,
                    "score": score,
                    "country": data.get('countryCode'),
                    "isp": data.get('isp'),
                    "total_reports": data.get('totalReports'),
                    "last_reported": data.get('lastReportedAt')
                }
            elif response.status_code == 429:
                return {"error": "Rate Limit Exceeded", "reputation": "Unknown"}
            elif response.status_code == 422: # Unprocessable e.g. private IP
                return {"error": "Unprocessable IP", "reputation": "Unknown"}
            else:
                return {"error": f"HTTP {response.status_code}", "reputation": "Unknown"}
        except Exception as e:
            return {"error": str(e), "reputation": "Unknown"}

class ReputationChecker:
    def __init__(self, vt_key=None, abuse_key=None, proxy_settings=None):
        self.vt = VirusTotalChecker(vt_key, proxy_settings)
        self.abuse = AbuseIPDBChecker(abuse_key, proxy_settings)
        # Helper to classify
        self.classifier = BaseChecker() 

    def classify_indicator(self, indicator):
        return self.classifier.classify_indicator(indicator)

    def check_indicator(self, indicator, enable_vt=True, enable_abuse=False):
        result = {
            "indicator": indicator,
            "type": self.classify_indicator(indicator),
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "final_verdict": "Unknown"
        }
        
        vt_res = {}
        abuse_res = {}
        
        # VirusTotal Check
        if enable_vt:
            vt_res = self.vt.check(indicator)
            result["vt"] = vt_res
            
        # AbuseIPDB Check
        if enable_abuse:
            abuse_res = self.abuse.check(indicator)
            result["abuseip"] = abuse_res
            
        # Verdict Logic
        # Priority: Malicious > Suspicious > Safe > Unknown
        verdicts = []
        if enable_vt and "reputation" in vt_res:
            verdicts.append(vt_res["reputation"])
        if enable_abuse and "reputation" in abuse_res:
             verdicts.append(abuse_res["reputation"])
             
        if "Malicious" in verdicts:
            result["final_verdict"] = "Malicious"
        elif "Suspicious" in verdicts:
            result["final_verdict"] = "Suspicious"
        elif "Safe" in verdicts:
            result["final_verdict"] = "Safe"
        elif not verdicts:
            result["final_verdict"] = "Skipped"

        return result
