class InvestigationCase:
    """
    Standard investigation case used throughout SentinelChain.

    Each agent can read information from the case and add
    its own findings without changing the overall structure.
    """

    def __init__(self, parsed_alert, case_id):

        self.case = {

            # Case information
            "case_id": case_id,
            "status": "open",

            # Original alert
            "alert": parsed_alert.get(
                "alert",
                {}
            ),

            # Parsed context
            "endpoint": parsed_alert.get(
                "endpoint",
                {}
            ),

            "network": parsed_alert.get(
                "network",
                {}
            ),

            "user": parsed_alert.get(
                "user",
                {}
            ),

            "process": parsed_alert.get(
                "process",
                {}
            ),

            "authentication": parsed_alert.get(
                "authentication",
                {}
            ),

            "mitre": parsed_alert.get(
                "mitre",
                {}
            ),

            # Investigation data
            "evidence": [],

            "timeline": [],

            # Agent results
            "triage": {},

            "threat_intelligence": {},

            "findings": [],

            "counter_analysis": {},

            "verdict": {}
        }

    def get_case(self):
        """
        Return the complete investigation case.
        """
        return self.case

    def update_triage(self, triage_result):
        """
        Store Agent 1's triage result in the investigation case.
        """
        self.case["triage"] = triage_result 