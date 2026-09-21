import json


class ReportGenerator:

    def __init__(self, investigation_case):
        self.case = investigation_case

    def section(self, title):
        return (
            "\n"
            + "-" * 70
            + "\n"
            + title
            + "\n"
            + "-" * 70
        )

    def bullet_list(self, items):
        if not items:
            return "None identified."

        return "\n".join(
            f"• {item}"
            for item in items
        )

    def generate(self):

        case = self.case

        alert = case.get("alert", {})
        endpoint = case.get("endpoint", {})
        triage = case.get("triage", {})
        evidence = case.get("evidence", {})
        threat_intel = case.get(
            "threat_intelligence", {}
        )
        correlation = case.get(
            "correlation", {}
        )
        investigation = case.get(
            "investigation", {}
        )
        counter_analysis = case.get(
            "counter_analysis", {}
        )
        verdict = case.get(
            "verdict", {}
        )

        rule = alert.get("rule", {})

        report = []

        # =====================================================
        # HEADER
        # =====================================================

        report.append("=" * 70)
        report.append(
            "                     SENTINELCHAIN AI"
        )
        report.append(
            "                  SECURITY INVESTIGATION"
        )
        report.append("=" * 70)

        # =====================================================
        # CASE INFORMATION
        # =====================================================

        report.append(
            self.section("CASE INFORMATION")
        )

        report.append(
            f"Case ID        : "
            f"{case.get('case_id', 'Unknown')}"
        )

        report.append(
            f"Alert ID       : "
            f"{alert.get('alert_id', 'Unknown')}"
        )

        report.append(
            f"Detection      : "
            f"{rule.get('description', 'Unknown')}"
        )

        report.append(
            f"Rule ID        : "
            f"{rule.get('id', 'Unknown')}"
        )

        report.append(
            f"Severity       : "
            f"Level {rule.get('level', 'Unknown')}"
        )

        report.append(
            f"Timestamp      : "
            f"{alert.get('timestamp', 'Unknown')}"
        )

        report.append(
            f"Host           : "
            f"{endpoint.get('agent_name', 'Unknown')}"
        )

        # =====================================================
        # WHAT HAPPENED
        # =====================================================

        report.append(
            self.section("WHAT HAPPENED")
        )

        report.append(
            triage.get(
                "summary",
                "No summary available."
            )
        )

        # =====================================================
        # INITIAL TRIAGE
        # =====================================================

        report.append(
            self.section("INITIAL TRIAGE")
        )

        report.append(
            f"Category       : "
            f"{triage.get('category', 'Unknown').upper()}"
        )

        report.append(
            f"Priority       : "
            f"{triage.get('priority', 'Unknown').upper()}"
        )

        investigation_required = triage.get(
            "investigation_required",
            False
        )

        report.append(
            f"Investigation  : "
            f"{'REQUIRED' if investigation_required else 'NOT REQUIRED'}"
        )

        report.append("\nReason:")
        report.append(
            triage.get(
                "reason",
                "No reason provided."
            )
        )

        # =====================================================
        # EVIDENCE
        # =====================================================

        report.append(
            self.section("EVIDENCE")
        )

        report.append("\nEvidence Found:")
        report.append(
            self.bullet_list(
                evidence.get(
                    "evidence_found",
                    []
                )
            )
        )

        report.append("\nEvidence Missing:")
        report.append(
            self.bullet_list(
                evidence.get(
                    "evidence_missing",
                    []
                )
            )
        )

        report.append("\nObservations:")
        report.append(
            self.bullet_list(
                evidence.get(
                    "observations",
                    []
                )
            )
        )

        # =====================================================
        # THREAT INTELLIGENCE
        # =====================================================

        report.append(
            self.section("THREAT INTELLIGENCE")
        )

        indicators = threat_intel.get(
            "indicators_found",
            []
        )

        if indicators:
            report.append("Indicators Identified:")

            for indicator in indicators:
                report.append(
                    f"• {indicator.get('type', 'unknown')}: "
                    f"{indicator.get('value', 'unknown')}"
                )

        else:
            report.append(
                "No actionable indicators were identified."
            )

        ti_results = threat_intel.get(
            "threat_intelligence",
            []
        )

        if ti_results:
            report.append(
                "\nThreat Intelligence Findings:"
            )

            report.append(
                self.bullet_list(ti_results)
            )

        # =====================================================
        # CORRELATION
        # =====================================================

        report.append(
            self.section("CORRELATION")
        )

        correlations = correlation.get(
            "correlations",
            []
        )

        if correlations:

            for item in correlations:

                relationship = item.get(
                    "relationship",
                    "Unknown relationship"
                )

                significance = item.get(
                    "significance",
                    "Unknown"
                )

                report.append(
                    f"• {relationship} "
                    f"[Significance: {significance}]"
                )

        else:

            report.append(
                "No meaningful correlations were identified."
            )

        patterns = correlation.get(
            "patterns",
            []
        )

        if patterns:

            report.append("\nObserved Patterns:")
            report.append(
                self.bullet_list(patterns)
            )

        # =====================================================
        # INVESTIGATION
        # =====================================================

        report.append(
            self.section("INVESTIGATION FINDINGS")
        )

        findings = investigation.get(
            "investigation_findings",
            []
        )

        if findings:

            for finding in findings:

                finding_text = finding.get(
                    "finding",
                    "Unknown finding"
                )

                finding_type = finding.get(
                    "type",
                    "unknown"
                )

                significance = finding.get(
                    "significance",
                    "unknown"
                )

                report.append(
                    f"• [{finding_type.upper()}] "
                    f"{finding_text}"
                )

                report.append(
                    f"  Significance: "
                    f"{significance}"
                )

        else:

            report.append(
                "No investigation findings were identified."
            )

        activity_summary = investigation.get(
            "activity_summary"
        )

        if activity_summary:

            report.append("\nActivity Summary:")
            report.append(activity_summary)

        # =====================================================
        # COUNTER-ANALYSIS
        # =====================================================

        report.append(
            self.section("COUNTER-ANALYSIS")
        )

        challenges = counter_analysis.get(
            "challenges",
            []
        )

        if challenges:

            for challenge in challenges:

                report.append(
                    f"• Challenge: "
                    f"{challenge.get('challenge', '')}"
                )

                report.append(
                    f"  Alternative explanation: "
                    f"{challenge.get('alternative_explanation', '')}"
                )

                report.append(
                    f"  Strength: "
                    f"{challenge.get('strength', 'unknown')}"
                )

        else:

            report.append(
                "No significant challenges were identified."
            )

        uncertainties = counter_analysis.get(
            "uncertainties",
            []
        )

        if uncertainties:

            report.append("\nUncertainties:")
            report.append(
                self.bullet_list(uncertainties)
            )

        # =====================================================
        # FINAL ASSESSMENT
        # =====================================================

        report.append(
            self.section("FINAL ASSESSMENT")
        )

        final_verdict = verdict.get(
            "verdict",
            "unknown"
        )

        confidence = verdict.get(
            "confidence",
            "unknown"
        )

        escalation = verdict.get(
            "recommended_escalation",
            False
        )

        report.append(
            f"VERDICT        : "
            f"{final_verdict.upper()}"
        )

        report.append(
            f"CONFIDENCE     : "
            f"{confidence.upper()}"
        )

        report.append(
            f"ESCALATION     : "
            f"{'YES' if escalation else 'NO'}"
        )

        report.append("\nSummary:")
        report.append(
            verdict.get(
                "summary",
                "No final assessment available."
            )
        )

        # =====================================================
        # REASONING
        # =====================================================

        reasoning = verdict.get(
            "reasoning",
            []
        )

        if reasoning:

            report.append(
                "\nDecision Reasoning:"
            )

            report.append(
                self.bullet_list(reasoning)
            )

        # =====================================================
        # KEY EVIDENCE
        # =====================================================

        key_evidence = verdict.get(
            "key_evidence",
            []
        )

        if key_evidence:

            report.append(
                "\nKey Evidence:"
            )

            report.append(
                self.bullet_list(key_evidence)
            )

        # =====================================================
        # COUNTER EVIDENCE
        # =====================================================

        counter_evidence = verdict.get(
            "counter_evidence",
            []
        )

        if counter_evidence:

            report.append(
                "\nCounter Evidence:"
            )

            report.append(
                self.bullet_list(counter_evidence)
            )

        # =====================================================
        # RECOMMENDED NEXT STEPS
        # =====================================================

        next_steps = investigation.get(
            "investigation_next_steps",
            []
        )

        if next_steps:

            report.append(
                self.section(
                    "RECOMMENDED NEXT STEPS"
                )
            )

            for index, step in enumerate(
                next_steps,
                start=1
            ):

                report.append(
                    f"{index}. {step}"
                )

        # =====================================================
        # FOOTER
        # =====================================================

        report.append("\n" + "=" * 70)
        report.append(
            "                  END OF INVESTIGATION"
        )
        report.append("=" * 70)

        return "\n".join(report)