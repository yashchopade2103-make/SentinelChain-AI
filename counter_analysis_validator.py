import json


class CounterAnalysisValidator:

    REQUIRED_FIELDS = [
        "challenges",
        "assumptions_identified",
        "supporting_factors",
        "uncertainties",
        "recommended_verifications",
        "summary"
    ]

    ALLOWED_STRENGTHS = {
        "low",
        "medium",
        "high"
    }

    def validate(self, raw_output):

        # CrewAI may return an object containing the actual raw response.
        if hasattr(raw_output, "raw"):
            raw_output = raw_output.raw

        # Make sure we are validating a string.
        if not isinstance(raw_output, str):
            raw_output = str(raw_output)

        # ---------------------------------------------------------
        # 1. Validate JSON
        # ---------------------------------------------------------

        try:
            data = json.loads(raw_output)

        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"

        # ---------------------------------------------------------
        # 2. Validate root object
        # ---------------------------------------------------------

        if not isinstance(data, dict):
            return False, "JSON root must be an object."

        # ---------------------------------------------------------
        # 3. Validate required fields
        # ---------------------------------------------------------

        for field in self.REQUIRED_FIELDS:

            if field not in data:
                return False, f"Missing required field: {field}"

        # ---------------------------------------------------------
        # 4. Validate challenges
        # ---------------------------------------------------------

        challenges = data["challenges"]

        if not isinstance(challenges, list):
            return False, "challenges must be a list."

        for index, challenge in enumerate(challenges):

            if not isinstance(challenge, dict):
                return False, (
                    f"challenges[{index}] must be an object."
                )

            required_challenge_fields = [
                "finding_challenged",
                "challenge",
                "alternative_explanation",
                "strength"
            ]

            for field in required_challenge_fields:

                if field not in challenge:
                    return False, (
                        f"challenges[{index}] "
                        f"missing field: {field}"
                    )

            # finding_challenged
            if not isinstance(
                challenge["finding_challenged"],
                str
            ):
                return False, (
                    f"challenges[{index}].finding_challenged "
                    "must be a string."
                )

            if not challenge["finding_challenged"].strip():
                return False, (
                    f"challenges[{index}].finding_challenged "
                    "cannot be empty."
                )

            # challenge
            if not isinstance(
                challenge["challenge"],
                str
            ):
                return False, (
                    f"challenges[{index}].challenge "
                    "must be a string."
                )

            if not challenge["challenge"].strip():
                return False, (
                    f"challenges[{index}].challenge "
                    "cannot be empty."
                )

            # alternative_explanation
            if not isinstance(
                challenge["alternative_explanation"],
                str
            ):
                return False, (
                    f"challenges[{index}].alternative_explanation "
                    "must be a string."
                )

            if not challenge["alternative_explanation"].strip():
                return False, (
                    f"challenges[{index}].alternative_explanation "
                    "cannot be empty."
                )

            # strength
            if challenge["strength"] not in self.ALLOWED_STRENGTHS:
                return False, (
                    f"Invalid challenge strength: "
                    f"{challenge['strength']}"
                )

        # ---------------------------------------------------------
        # 5. Validate assumptions_identified
        # ---------------------------------------------------------

        assumptions = data["assumptions_identified"]

        if not isinstance(assumptions, list):
            return False, (
                "assumptions_identified must be a list."
            )

        for index, item in enumerate(assumptions):

            if not isinstance(item, str):
                return False, (
                    f"assumptions_identified[{index}] "
                    "must be a string."
                )

            if not item.strip():
                return False, (
                    f"assumptions_identified[{index}] "
                    "cannot be empty."
                )

        # ---------------------------------------------------------
        # 6. Validate supporting_factors
        # ---------------------------------------------------------

        supporting_factors = data["supporting_factors"]

        if not isinstance(supporting_factors, list):
            return False, (
                "supporting_factors must be a list."
            )

        for index, item in enumerate(supporting_factors):

            if not isinstance(item, str):
                return False, (
                    f"supporting_factors[{index}] "
                    "must be a string."
                )

            if not item.strip():
                return False, (
                    f"supporting_factors[{index}] "
                    "cannot be empty."
                )

        # ---------------------------------------------------------
        # 7. Validate uncertainties
        # ---------------------------------------------------------

        uncertainties = data["uncertainties"]

        if not isinstance(uncertainties, list):
            return False, (
                "uncertainties must be a list."
            )

        for index, item in enumerate(uncertainties):

            if not isinstance(item, str):
                return False, (
                    f"uncertainties[{index}] "
                    "must be a string."
                )

            if not item.strip():
                return False, (
                    f"uncertainties[{index}] "
                    "cannot be empty."
                )

        # ---------------------------------------------------------
        # 8. Validate recommended_verifications
        # ---------------------------------------------------------

        verifications = data["recommended_verifications"]

        if not isinstance(verifications, list):
            return False, (
                "recommended_verifications must be a list."
            )

        for index, item in enumerate(verifications):

            if not isinstance(item, str):
                return False, (
                    f"recommended_verifications[{index}] "
                    "must be a string."
                )

            if not item.strip():
                return False, (
                    f"recommended_verifications[{index}] "
                    "cannot be empty."
                )

        # ---------------------------------------------------------
        # 9. Validate summary
        # ---------------------------------------------------------

        if not isinstance(data["summary"], str):
            return False, "summary must be a string."

        if not data["summary"].strip():
            return False, "summary cannot be empty."

        # ---------------------------------------------------------
        # 10. Validation successful
        # ---------------------------------------------------------

        return True, data