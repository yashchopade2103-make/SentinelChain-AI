import requests
import urllib3

# Disable warnings caused by Wazuh's self-signed HTTPS certificates.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhAPIClient:

    def __init__(
        self,
        wazuh_host,
        wazuh_username,
        wazuh_password,
        indexer_username,
        indexer_password
    ):
        # Wazuh Server API
        self.api_url = f"https://{wazuh_host}:55000"

        # Wazuh Indexer API
        self.indexer_url = f"https://{wazuh_host}:9200"

        # Wazuh Server API credentials
        self.wazuh_username = wazuh_username
        self.wazuh_password = wazuh_password

        # Wazuh Indexer credentials
        self.indexer_username = indexer_username
        self.indexer_password = indexer_password

        # JWT token for Wazuh Server API
        self.token = None

    # ---------------------------------------------------------
    # WAZUH SERVER API AUTHENTICATION
    # ---------------------------------------------------------

    def authenticate(self):

        url = f"{self.api_url}/security/user/authenticate"

        response = requests.post(
            url,
            auth=(
                self.wazuh_username,
                self.wazuh_password
            ),
            verify=False,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        self.token = data["data"]["token"]

        print("[+] Wazuh Server API authentication successful.")

        return self.token

    # ---------------------------------------------------------
    # GET ALERTS FROM WAZUH INDEXER
    # ---------------------------------------------------------

    def get_alerts(self, limit=5):

        url = (
            f"{self.indexer_url}/"
            "wazuh-alerts-4.x-*/_search"
        )

        query = {
            "size": limit,

            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ]
        }

        response = requests.post(
            url,
            auth=(
                self.indexer_username,
                self.indexer_password
            ),
            json=query,
            verify=False,
            timeout=10
        )

        print(
            f"[+] Wazuh Indexer response: "
            f"{response.status_code}"
        )

        response.raise_for_status()

        return response.json()

    # ---------------------------------------------------------
    # GET A SINGLE LATEST ALERT
    # ---------------------------------------------------------

    def get_latest_alert(self):

        alerts = self.get_alerts(limit=1)

        hits = alerts.get("hits", {}).get("hits", [])

        if not hits:
            return None

        return hits[0]

    # ---------------------------------------------------------
    # PRINT ALERT SUMMARY
    # ---------------------------------------------------------

    def print_alert_summary(self, alert):

        if not alert:
            print("[-] No alert found.")
            return

        source = alert.get("_source", {})

        rule = source.get("rule", {})
        agent = source.get("agent", {})

        print("\n" + "=" * 60)
        print("WAZUH ALERT")
        print("=" * 60)

        print(
            "Alert ID:",
            source.get("id")
        )

        print(
            "Rule ID:",
            rule.get("id")
        )

        print(
            "Description:",
            rule.get("description")
        )

        print(
            "Severity:",
            rule.get("level")
        )

        print(
            "Timestamp:",
            source.get("@timestamp")
        )

        print(
            "Agent:",
            agent.get("name")
        )

        print(
            "Agent IP:",
            agent.get("ip")
        )

        print(
            "Decoder:",
            source.get("decoder", {}).get("name")
        )

        print(
            "Full Log:",
            source.get("full_log")
        )

        print("=" * 60)


# -------------------------------------------------------------
# TESTING
# -------------------------------------------------------------

if __name__ == "__main__":

    client = WazuhAPIClient(

        wazuh_host="10.87.73.108",

        # Wazuh Server API
        wazuh_username="wazuh",
        wazuh_password="AwpH0S?XTFzRK?*vJ*vBubv5FskdlT1N",

        # Wazuh Indexer
        indexer_username="admin",
        indexer_password="vSY4*EG0n50npWuLEQUzclgC42Fg?W6X"
    )

    # Test Wazuh Server API authentication
    client.authenticate()

    # Get latest alerts
    alerts = client.get_alerts(limit=5)

    hits = alerts.get(
        "hits",
        {}
    ).get(
        "hits",
        []
    )

    print(
        "\n[+] Alerts returned:",
        len(hits)
    )

    # Display summaries
    for alert in hits:
        client.print_alert_summary(alert)