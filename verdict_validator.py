import json


class VerdictValidator:

    REQUIRED_FIELDS = [
        "verdict",
        "confidence",
        "summary",
        "reasoning",
        "key_evidence",
        "counter_evidence",
        "uncertainties",
        "recommended_escalation"
    ]

    ALLOWED_VERDICTS = {
        "benign",
        "suspicious",
        "malicious",
        "inconclusive"
    }

    ALLOWED_CONFIDENCE = {
        "low",
        "medium",
        "high"
    }

    def validate(self, raw_output):

        if hasattr(raw_output, "raw"):
            raw_output = raw_output.raw

        if not isinstance(raw_output, str):
            raw_output = str(raw_output)

        try:
            data = json.loads(raw_output)

        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"

        if not isinstance(data, dict):
            return False, "JSON root must be an object."

        # Check required fields
        for field in self.REQUIRED_FIELDS:

            if field not in data:
                return False, f"Missing required field: {field}"

        # Verdict
        if data["verdict"] not in self.ALLOWED_VERDICTS:

            return False, (
                f"Invalid verdict: {data['verdict']}"
            )

        # Confidence
        if data["confidence"] not in self.ALLOWED_CONFIDENCE:

            return False, (
                f"Invalid confidence: {data['confidence']}"
            )

        # Summary
        if not isinstance(data["summary"], str):
            return False, "summary must be a string."

        if not data["summary"].strip():
            return False, "summary cannot be empty."

        # List fields
        list_fields = [
            "reasoning",
            "key_evidence",
            "counter_evidence",
            "uncertainties"
        ]

        for field in list_fields:

            if not isinstance(data[field], list):

                return False, (
                    f"{field} must be a list."
                )

            for index, item in enumerate(data[field]):

                if not isinstance(item, str):

                    return False, (
                        f"{field}[{index}] must be a string."
                    )

                if not item.strip():

                    return False, (
                        f"{field}[{index}] cannot be empty."
                    )

        # Escalation
        if not isinstance(
            data["recommended_escalation"],
            bool
        ):

            return False, (
                "recommended_escalation must be a boolean."
            )

        return True, data