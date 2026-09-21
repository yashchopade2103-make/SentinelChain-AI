import requests


class AbuseIPDBLookup:
    """
    Threat-intelligence tool for checking IP reputation
    using the AbuseIPDB API v2.
    """

    def __init__(self, api_key):
        self.api_key = api_key
        self.url = "https://api.abuseipdb.com/api/v2/check"

    def check_ip(self, ip_address):
        """
        Check the reputation of a single IP address.
        """

        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }

        try:
            response = requests.get(
                self.url,
                headers=headers,
                params=params,
                timeout=15
            )

            if response.status_code != 200:
                return {
                    "success": False,
                    "ip": ip_address,
                    "error": f"AbuseIPDB returned HTTP {response.status_code}",
                    "details": response.text
                }

            result = response.json()

            data = result.get("data", {})

            return {
                "success": True,
                "ip": data.get("ipAddress"),
                "abuse_confidence_score": data.get(
                    "abuseConfidenceScore"
                ),
                "total_reports": data.get(
                    "totalReports"
                ),
                "country_code": data.get(
                    "countryCode"
                ),
                "country_name": data.get(
                    "countryName"
                ),
                "usage_type": data.get(
                    "usageType"
                ),
                "isp": data.get(
                    "isp"
                ),
                "domain": data.get(
                    "domain"
                ),
                "last_reported_at": data.get(
                    "lastReportedAt"
                )
            }

        except requests.exceptions.Timeout:

            return {
                "success": False,
                "ip": ip_address,
                "error": "Request timed out"
            }

        except requests.exceptions.RequestException as e:

            return {
                "success": False,
                "ip": ip_address,
                "error": str(e)
            }