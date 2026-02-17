import requests
import json
from datetime import datetime, timedelta
from ipaddress import ip_address


class ThreatIntelChecker:
    def __init__(self, api_key=None, cache_duration=3600):
        self.api_key = api_key
        self.cache = {}
        self.cache_duration = cache_duration

    def check_ip(self, ip_address):
        if ip_address in self.cache:
            cached_data, cached_time = self.cache[ip_address]
            if datetime.now() - cached_time < timedelta(seconds=self.cache_duration):
                return cached_data

        if self._is_private_ip(ip_address):
            return {
                "ip": ip_address,
                "is_private": True,
                "is_malicious": False,
                "abuse_confidence_score": 0,
            }

        if not self.api_key:
            return {
                "ip": ip_address,
                "error": "No API key configured",
                "is_malicious": None,
            }

        result = self._query_abuseipdb(ip_address)

        if result:
            self.cache[ip_address] = (result, datetime.now())

        return result

    def _query_abuseipdb(self, ip_address):
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": self.api_key}
        params = {"ipAddress": ip_address, "maxAgeInDays": "90", "verbose": ""}

        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)

            if response.status_code == 200:
                data = response.json()["data"]
                return {
                    "ip": ip_address,
                    "abuse_confidence_score": data["abuseConfidenceScore"],
                    "is_malicious": data["abuseConfidenceScore"] > 50,
                    "total_reports": data["totalReports"],
                    "country_code": data.get("countryCode", "Unknown"),
                    "usage_type": data.get("usageType", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "domain": data.get("domain", "Unknown"),
                }
            elif response.status_code == 429:
                return {
                    "ip": ip_address,
                    "error": "Rate limit exceeded",
                    "is_malicious": None,
                }
            else:
                return {
                    "ip": ip_address,
                    "error": f"API error: {response.status_code}",
                    "is_malicious": None,
                }

        except requests.exceptions.Timeout:
            return {"ip": ip_address, "error": "Request timeout", "is_malicious": None}
        except Exception as e:
            return {"ip": ip_address, "error": str(e), "is_malicious": None}

    def _is_private_ip(self, ip_str):
        try:
            return ip_address(ip_str).is_private
        except ValueError:
            return False
