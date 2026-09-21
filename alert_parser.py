import re


class AlertParser:

    def __init__(self, alert):

        self.alert = alert

        # Wazuh stores the actual alert information
        # inside the "_source" field.
        self.source = alert.get("_source", {})

    # ---------------------------------------------------------
    # SAFE VALUE HELPER
    # ---------------------------------------------------------

    def get(self, dictionary, key, default=None):

        if not isinstance(dictionary, dict):
            return default

        return dictionary.get(key, default)

    # ---------------------------------------------------------
    # PARSE KEY/VALUE DATA FROM FULL LOG
    # ---------------------------------------------------------

    def parse_full_log(self, full_log):

        if not full_log:
            return {}

        # Example:
        # apparmor="AUDIT" operation="userns_create" pid=9393
        #
        # Extracts:
        # {
        #     "apparmor": "AUDIT",
        #     "operation": "userns_create",
        #     "pid": "9393"
        # }

        pattern = r'(\w+)=(".*?"|\S+)'

        matches = re.findall(pattern, full_log)

        parsed = {}

        for key, value in matches:

            value = value.strip('"')

            parsed[key] = value

        return parsed

    # ---------------------------------------------------------
    # PARSE SYSLOG DATA FROM FULL LOG
    # ---------------------------------------------------------

    def parse_syslog(self, full_log):

        if not full_log:
            return {}

        # Expected format:
        #
        # Sep 05 16:45:25 siemserver ssh-agent[2293]: exiting on signal 15
        #
        # Groups:
        # timestamp
        # hostname
        # process name
        # process ID
        # message

        pattern = (
            r'^(?P<timestamp>\w+\s+\d+\s+'
            r'\d+:\d+:\d+)\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<process>[^\s\[]+)'
            r'(?:\[(?P<pid>\d+)\])?:\s*'
            r'(?P<message>.*)$'
        )

        match = re.match(pattern, full_log)

        if not match:
            return {}

        return {
            "timestamp": match.group("timestamp"),
            "hostname": match.group("hostname"),
            "process": match.group("process"),
            "pid": match.group("pid"),
            "message": match.group("message")
        }

    # ---------------------------------------------------------
    # PARSE ALERT
    # ---------------------------------------------------------

    def parse(self):

        source = self.source

        agent = source.get("agent", {})
        rule = source.get("rule", {})
        data = source.get("data", {})
        decoder = source.get("decoder", {})
        predecoder = source.get("predecoder", {})

        # -----------------------------------------------------
        # FULL LOG
        # -----------------------------------------------------

        full_log = source.get("full_log", "")

        # Parse key=value style logs
        log_data = self.parse_full_log(full_log)

        # Parse traditional syslog style logs
        syslog_data = self.parse_syslog(full_log)

        # -----------------------------------------------------
        # MITRE
        # -----------------------------------------------------

        mitre = rule.get("mitre", {})

        # -----------------------------------------------------
        # ALERT INFORMATION
        # -----------------------------------------------------

        alert_information = {

            "alert_id": source.get("id"),

            "timestamp": source.get("@timestamp"),

            "rule": {
                "id": rule.get("id"),
                "description": rule.get("description"),
                "level": rule.get("level"),
                "groups": rule.get("groups", [])
            },

            "decoder": {
                "name": decoder.get("name"),
                "parent": decoder.get("parent")
            }
        }

        # -----------------------------------------------------
        # AGENT / ENDPOINT
        # -----------------------------------------------------

        endpoint = {

            "agent_id": agent.get("id"),

            "agent_name": agent.get("name"),

            "agent_ip": agent.get("ip"),

            "hostname": (
                predecoder.get("hostname")
                or syslog_data.get("hostname")
            )
        }

        # -----------------------------------------------------
        # NETWORK INFORMATION
        # -----------------------------------------------------

        network = {

            "source_ip": (
                data.get("srcip")
                or log_data.get("srcip")
                or log_data.get("src_ip")
            ),

            "source_port": (
                data.get("srcport")
                or log_data.get("srcport")
                or log_data.get("src_port")
            ),

            "destination_ip": (
                data.get("dstip")
                or log_data.get("dstip")
                or log_data.get("dst_ip")
            ),

            "destination_port": (
                data.get("dstport")
                or log_data.get("dstport")
                or log_data.get("dst_port")
            ),

            "protocol": (
                data.get("protocol")
                or log_data.get("protocol")
            )
        }

        # -----------------------------------------------------
        # USER INFORMATION
        # -----------------------------------------------------

        user = {

            "source_user": (
                data.get("srcuser")
                or log_data.get("srcuser")
                or log_data.get("src_user")
            ),

            "destination_user": (
                data.get("dstuser")
                or log_data.get("dstuser")
                or log_data.get("dst_user")
            ),

            "username": (
                data.get("user")
                or log_data.get("user")
                or log_data.get("username")
            )
        }

        # -----------------------------------------------------
        # PROCESS INFORMATION
        # -----------------------------------------------------

        process = {

            "process_name": (
                data.get("process")
                or data.get("process_name")
                or log_data.get("process")
                or log_data.get("process_name")
                or log_data.get("comm")
                or syslog_data.get("process")
            ),

            "process_id": (
                data.get("pid")
                or log_data.get("pid")
                or syslog_data.get("pid")
            ),

            "command": (
                data.get("command")
                or log_data.get("command")
            ),

            "file": (
                data.get("file")
                or log_data.get("file")
                or log_data.get("filename")
            )
        }

        # -----------------------------------------------------
        # AUTHENTICATION
        # -----------------------------------------------------

        authentication = {

            "result": (
                data.get("status")
                or log_data.get("status")
                or log_data.get("result")
            ),

            "src_user": (
                data.get("srcuser")
                or log_data.get("srcuser")
                or log_data.get("src_user")
            ),

            "dst_user": (
                data.get("dstuser")
                or log_data.get("dstuser")
                or log_data.get("dst_user")
            )
        }

        # -----------------------------------------------------
        # MITRE ATT&CK
        # -----------------------------------------------------

        mitre_information = {

            "techniques": mitre.get(
                "technique",
                []
            ),

            "technique_ids": mitre.get(
                "id",
                []
            ),

            "tactics": mitre.get(
                "tactic",
                []
            )
        }

        # -----------------------------------------------------
        # RAW EVENT
        # -----------------------------------------------------

        raw_event = {

            "full_log": full_log,

            "parsed_log_data": log_data,

            "syslog_data": syslog_data,

            "location": source.get("location"),

            "input_type": source.get(
                "input",
                {}
            ).get(
                "type"
            )
        }

        # -----------------------------------------------------
        # FINAL STRUCTURED EVENT
        # -----------------------------------------------------

        parsed_alert = {

            "alert": alert_information,

            "endpoint": endpoint,

            "network": network,

            "user": user,

            "process": process,

            "authentication": authentication,

            "mitre": mitre_information,

            "raw_event": raw_event
        }

        return parsed_alert