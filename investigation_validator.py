import json


class InvestigationValidator:

    REQUIRED_FIELDS = [
        "investigation_findings",
        "activity_summary",
        "evidence_supporting_findings",
        "evidence_gaps",
        "investigation_next_steps",
        "summary"
    ]

    ALLOWED_TYPES = {
        "confirmed",
        "inference",
        "uncertain"
    }

    ALLOWED_SIGNIFICANCE = {
        "low",
        "medium",
        "high"
    }

    def validate(self, raw_output):

        # ---------------------------------------------------------
        # 1. Parse JSON
        # ---------------------------------------------------------

        if hasattr(raw_output, "raw"):
            raw_output = raw_output.raw

        if not isinstance(raw_output, str):
            raw_output = str(raw_output)

        try:
            data = json.loads(raw_output)

        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"

        # ---------------------------------------------------------
        # 2. Root object
        # ---------------------------------------------------------

        if not isinstance(data, dict):
            return False, "JSON root must be an object."

        # ---------------------------------------------------------
        # 3. Required fields
        # ---------------------------------------------------------

        for field in self.REQUIRED_FIELDS:
            if field not in data:
                return False, f"Missing required field: {field}"

        # ---------------------------------------------------------
        # 4. Check investigation_findings
        # ---------------------------------------------------------

        findings = data["investigation_findings"]

        if not isinstance(findings, list):
            return False, "investigation_findings must be a list."

        for index, finding in enumerate(findings):

            if not isinstance(finding, dict):
                return False, (
                    f"investigation_findings[{index}] "
                    "must be an object."
                )

            required_finding_fields = [
                "finding",
                "type",
                "significance"
            ]

            for field in required_finding_fields:
                if field not in finding:
                    return False, (
                        f"investigation_findings[{index}] "
                        f"missing field: {field}"
                    )

            if not isinstance(finding["finding"], str):
                return False, (
                    f"investigation_findings[{index}].finding "
                    "must be a string."
                )

            if not finding["finding"].strip():
                return False, (
                    f"investigation_findings[{index}].finding "
                    "cannot be empty."
                )

            if finding["type"] not in self.ALLOWED_TYPES:
                return False, (
                    f"Invalid finding type: "
                    f"{finding['type']}"
                )

            if finding["significance"] not in self.ALLOWED_SIGNIFICANCE:
                return False, (
                    f"Invalid finding significance: "
                    f"{finding['significance']}"
                )

        # ---------------------------------------------------------
        # 5. Check activity_summary
        # ---------------------------------------------------------

        if not isinstance(data["activity_summary"], str):
            return False, "activity_summary must be a string."

        if not data["activity_summary"].strip():
            return False, "activity_summary cannot be empty."

        # ---------------------------------------------------------
        # 6. Check evidence_supporting_findings
        # ---------------------------------------------------------

        supporting = data["evidence_supporting_findings"]

        if not isinstance(supporting, list):
            return False, (
                "evidence_supporting_findings must be a list."
            )

        for item in supporting:
            if not isinstance(item, str):
                return False, (
                    "Every evidence_supporting_findings "
                    "item must be a string."
                )

        # ---------------------------------------------------------
        # 7. Check evidence_gaps
        # ---------------------------------------------------------

        gaps = data["evidence_gaps"]

        if not isinstance(gaps, list):
            return False, "evidence_gaps must be a list."

        for item in gaps:
            if not isinstance(item, str):
                return False, (
                    "Every evidence_gaps item must be a string."
                )

        # ---------------------------------------------------------
        # 8. Check investigation_next_steps
        # ---------------------------------------------------------

        next_steps = data["investigation_next_steps"]

        if not isinstance(next_steps, list):
            return False, (
                "investigation_next_steps must be a list."
            )

        for item in next_steps:
            if not isinstance(item, str):
                return False, (
                    "Every investigation_next_steps "
                    "item must be a string."
                )

        # ---------------------------------------------------------
        # 9. Check summary
        # ---------------------------------------------------------

        if not isinstance(data["summary"], str):
            return False, "summary must be a string."

        if not data["summary"].strip():
            return False, "summary cannot be empty."

        # ---------------------------------------------------------
        # 10. Validation successful
        # ---------------------------------------------------------

        return True, data