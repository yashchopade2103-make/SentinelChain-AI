import io
import json
import os
import sys
import threading
import time
from contextlib import redirect_stdout, redirect_stderr

from dotenv import load_dotenv
from crewai import Crew

from wazuh.wazuh_api import WazuhAPIClient
from parser.alert_parser import AlertParser
from schemas.investigation_case import InvestigationCase

from agents.triage_agent import AlertTriageAgent
from tasks.triage_task import TriageTask

from agents.evidence_agent import EvidenceAnalysisAgent
from tasks.evidence_task import EvidenceAnalysisTask

from agents.threat_intel_agent import ThreatIntelligenceAgent
from tasks.threat_intel_task import ThreatIntelligenceTask

from agents.correlation_agent import CorrelationAgent
from tasks.correlation_task import CorrelationTask

from agents.investigation_agent import InvestigationAgent
from tasks.investigation_task import InvestigationTask

from agents.counter_analysis_agent import CounterAnalysisAgent
from tasks.counter_analysis_task import CounterAnalysisTask

from agents.verdict_agent import FinalVerdictAgent
from tasks.verdict_task import FinalVerdictTask

from tools.ioc_extractor import IOCExtractor
from tools.abuseipdb_lookup import AbuseIPDBLookup

from utils.investigation_validator import InvestigationValidator
from utils.counter_analysis_validator import CounterAnalysisValidator
from utils.verdict_validator import VerdictValidator


# =========================================================
# CONFIGURATION
# =========================================================

load_dotenv()

WAZUH_HOST = "10.68.224.108"

# Wazuh Server API
WAZUH_USERNAME = "wazuh"
WAZUH_PASSWORD = "AwpH0S?XTFzRK?*vJ*vBubv5FskdlT1N"

# Wazuh Indexer
INDEXER_USERNAME = "admin"
INDEXER_PASSWORD = "vSY4*EG0n50npWuLEQUzclgC42Fg?W6X"

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


# =========================================================
# USER INTERFACE
# =========================================================

def banner():
    print()
    print("=" * 70)
    print("                         SENTINELCHAIN AI")
    print("                    From Alert to Attack Story")
    print("=" * 70)
    print()


def print_success(message):
    print(f"\r[✓] {message}")


def print_failure(message):
    print(f"\r[✗] {message}")


def run_with_progress(message, function):
    """
    Run a function while displaying a simple loading animation.

    Internal CrewAI output is suppressed so the user only sees
    SentinelChain's progress.
    """

    stop_event = threading.Event()
    output_stream = sys.__stdout__

    def spinner():
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        index = 0

        while not stop_event.is_set():

            output_stream.write(
                f"\r[ {frames[index % len(frames)]} ] {message}..."
            )

            output_stream.flush()

            index += 1
            time.sleep(0.12)

    spinner_thread = threading.Thread(
        target=spinner,
        daemon=True
    )

    spinner_thread.start()

    try:

        # Hide CrewAI / LLM / library console output.
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = function()

    except Exception:

        stop_event.set()
        spinner_thread.join()

        output_stream.write("\r" + (" " * 100) + "\r")
        output_stream.flush()

        print_failure(f"{message} failed.")

        raise

    finally:

        stop_event.set()
        spinner_thread.join()

    output_stream.write("\r" + (" " * 100) + "\r")
    output_stream.flush()

    print_success(f"{message} complete.")

    return result


# =========================================================
# MAIN
# =========================================================

def main():

    banner()

    # =====================================================
    # 1. CONNECT TO WAZUH
    # =====================================================

    def connect_to_wazuh():

        client = WazuhAPIClient(
            wazuh_host=WAZUH_HOST,
            wazuh_username=WAZUH_USERNAME,
            wazuh_password=WAZUH_PASSWORD,
            indexer_username=INDEXER_USERNAME,
            indexer_password=INDEXER_PASSWORD
        )

        client.authenticate()

        return client

    try:

        client = run_with_progress(
            "Connecting to Wazuh",
            connect_to_wazuh
        )

    except Exception as e:

        print(f"\nError: {e}")
        return


    # =====================================================
    # 2. RETRIEVE LATEST ALERT
    # =====================================================

    try:

        alert = run_with_progress(
            "Retrieving latest security alert",
            client.get_latest_alert
        )

    except Exception as e:

        print(f"\nError: {e}")
        return

    if not alert:

        print_failure("No Wazuh alerts found.")
        return


    # =====================================================
    # 3. PARSE ALERT
    # =====================================================

    def parse_alert():

        parser = AlertParser(alert)

        return parser.parse()

    try:

        parsed_alert = run_with_progress(
            "Parsing security event",
            parse_alert
        )

    except Exception as e:

        print(f"\nError: {e}")
        return


    # =====================================================
    # 4. CREATE INVESTIGATION CASE
    # =====================================================

    def create_case():

        case = InvestigationCase(
            parsed_alert,
            "SC-0001"
        )

        return case

    try:

        case = run_with_progress(
            "Building investigation case",
            create_case
        )

    except Exception as e:

        print(f"\nError: {e}")
        return

    investigation_case = case.get_case()


    # =====================================================
    # 5. AGENT 1 — ALERT TRIAGE
    # =====================================================

    def run_triage():

        triage_agent = AlertTriageAgent().get_agent()

        triage_task = TriageTask(
            agent=triage_agent,
            investigation_case=investigation_case
        ).get_task()

        triage_crew = Crew(
            agents=[triage_agent],
            tasks=[triage_task],
            verbose=False
        )

        return triage_crew.kickoff()

    try:

        triage_result_raw = run_with_progress(
            "Analyzing alert",
            run_triage
        )

    except Exception as e:

        print(f"\nError: {e}")
        return


    # =====================================================
    # 6. VALIDATE AGENT 1
    # =====================================================

    try:

        triage_result = json.loads(
            str(triage_result_raw).strip()
        )

        required_triage_fields = [
            "category",
            "priority",
            "investigation_required",
            "summary",
            "reason"
        ]

        missing_triage_fields = [
            field
            for field in required_triage_fields
            if field not in triage_result
        ]

        if missing_triage_fields:

            raise ValueError(
                f"Missing fields: {missing_triage_fields}"
            )

    except Exception as e:

        print_failure("Alert analysis validation failed.")
        print(f"Error: {e}")
        return


    # =====================================================
    # 7. UPDATE CASE WITH AGENT 1
    # =====================================================

    case.update_triage(
        triage_result
    )


    # =====================================================
    # 8. AGENT 2 — EVIDENCE ANALYSIS
    # =====================================================

    def run_evidence():

        evidence_agent = EvidenceAnalysisAgent().get_agent()

        evidence_task = EvidenceAnalysisTask(
            agent=evidence_agent,
            investigation_case=case.get_case()
        ).get_task()

        evidence_crew = Crew(
            agents=[evidence_agent],
            tasks=[evidence_task],
            verbose=False
        )

        return evidence_crew.kickoff()

    try:

        evidence_result_raw = run_with_progress(
            "Reviewing available evidence",
            run_evidence
        )

    except Exception as e:

        print(f"\nError: {e}")
        return


    # =====================================================
    # 9. VALIDATE AGENT 2
    # =====================================================

    try:

        evidence_result = json.loads(
            str(evidence_result_raw).strip()
        )

        required_evidence_fields = [
            "evidence_found",
            "evidence_missing",
            "observations"
        ]

        for field in required_evidence_fields:

            if field not in evidence_result:

                raise ValueError(
                    f"Missing field: {field}"
                )

        if not isinstance(
            evidence_result["evidence_found"],
            list
        ):

            raise ValueError(
                "evidence_found must be a list."
            )

        if not isinstance(
            evidence_result["evidence_missing"],
            list
        ):

            raise ValueError(
                "evidence_missing must be a list."
            )

        if not isinstance(
            evidence_result["observations"],
            list
        ):

            raise ValueError(
                "observations must be a list."
            )

    except Exception as e:

        print_failure("Evidence analysis validation failed.")
        print(f"Error: {e}")
        return


    # =====================================================
    # 10. UPDATE CASE WITH AGENT 2
    # =====================================================

    investigation_case["evidence"] = evidence_result


    # =====================================================
    # 11. IOC EXTRACTION
    # =====================================================

    def extract_iocs():

        ioc_extractor = IOCExtractor(
            case.get_case()
        )

        return ioc_extractor.extract()

    try:

        ioc_result = run_with_progress(
            "Extracting indicators",
            extract_iocs
        )

    except Exception as e:

        print(f"\nError: {e}")
        return


    # =====================================================
    # 12. ABUSEIPDB THREAT INTELLIGENCE
    # =====================================================

    if not ABUSEIPDB_API_KEY:

        print_failure(
            "Threat intelligence API key not configured."
        )

        return


    def run_abuseipdb():

        abuseipdb = AbuseIPDBLookup(
            ABUSEIPDB_API_KEY
        )

        results = []

        for indicator in ioc_result["indicators"]:

            if indicator["type"] != "ip":
                continue

            ip = indicator["value"]

            try:

                result = abuseipdb.check_ip(ip)

                results.append(result)

            except Exception:
                pass

        return results

    try:

        threat_intelligence_results = run_with_progress(
            "Checking threat intelligence",
            run_abuseipdb
        )

    except Exception as e:

        print(f"\nError: {e}")
        return


    # =====================================================
    # 13. AGENT 3 — THREAT INTELLIGENCE
    # =====================================================

    def run_threat_intelligence():

        threat_intel_agent = (
            ThreatIntelligenceAgent()
            .get_agent()
        )

        threat_intel_task = ThreatIntelligenceTask(
            agent=threat_intel_agent,
            investigation_case=case.get_case(),
            threat_intelligence_data=(
                threat_intelligence_results
            )
        ).get_task()

        threat_intel_crew = Crew(
            agents=[threat_intel_agent],
            tasks=[threat_intel_task],
            verbose=False
        )

        return threat_intel_crew.kickoff()

    try:

        threat_intel_result_raw = run_with_progress(
            "Analyzing threat intelligence",
            run_threat_intelligence
        )

    except Exception as e:

        print(f"\nError: {e}")
        return


    # =====================================================
    # 14. VALIDATE AGENT 3
    # =====================================================

    try:

        threat_intel_result = json.loads(
            str(threat_intel_result_raw).strip()
        )

        required_threat_intel_fields = [
            "indicators_found",
            "indicators_checked",
            "threat_intelligence",
            "summary"
        ]

        for field in required_threat_intel_fields:

            if field not in threat_intel_result:

                raise ValueError(
                    f"Missing field: {field}"
                )

        if not isinstance(
            threat_intel_result["indicators_found"],
            list
        ):

            raise ValueError(
                "indicators_found must be a list."
            )

        if not isinstance(
            threat_intel_result["indicators_checked"],
            list
        ):

            raise ValueError(
                "indicators_checked must be a list."
            )

        if not isinstance(
            threat_intel_result["threat_intelligence"],
            list
        ):

            raise ValueError(
                "threat_intelligence must be a list."
            )

        if not isinstance(
            threat_intel_result["summary"],
            str
        ):

            raise ValueError(
                "summary must be a string."
            )

    except Exception as e:

        print_failure(
            "Threat intelligence validation failed."
        )

        print(f"Error: {e}")
        return


    # =====================================================
    # 15. UPDATE CASE WITH AGENT 3
    # =====================================================

    investigation_case[
        "threat_intelligence"
    ] = threat_intel_result


    # =====================================================
    # 16. AGENT 4 — CORRELATION
    # =====================================================

    def run_correlation():

        correlation_agent = (
            CorrelationAgent()
            .get_agent()
        )

        correlation_task = CorrelationTask(
            agent=correlation_agent,
            investigation_case=case.get_case()
        ).get_task()

        correlation_crew = Crew(
            agents=[correlation_agent],
            tasks=[correlation_task],
            verbose=False
        )

        return correlation_crew.kickoff()

    try:

        correlation_result_raw = run_with_progress(
            "Correlating investigation findings",
            run_correlation
        )

    except Exception as e:

        print(f"\nError: {e}")
        return


    # =====================================================
    # 17. VALIDATE AGENT 4
    # =====================================================

    try:

        correlation_result = json.loads(
            str(correlation_result_raw).strip()
        )

        required_correlation_fields = [
            "correlations",
            "supporting_evidence",
            "contradicting_evidence",
            "patterns",
            "summary"
        ]

        for field in required_correlation_fields:

            if field not in correlation_result:

                raise ValueError(
                    f"Missing field: {field}"
                )

        if not isinstance(
            correlation_result["correlations"],
            list
        ):

            raise ValueError(
                "correlations must be a list."
            )

        if not isinstance(
            correlation_result["supporting_evidence"],
            list
        ):

            raise ValueError(
                "supporting_evidence must be a list."
            )

        if not isinstance(
            correlation_result["contradicting_evidence"],
            list
        ):

            raise ValueError(
                "contradicting_evidence must be a list."
            )

        if not isinstance(
            correlation_result["patterns"],
            list
        ):

            raise ValueError(
                "patterns must be a list."
            )

        if not isinstance(
            correlation_result["summary"],
            str
        ):

            raise ValueError(
                "summary must be a string."
            )

        allowed_significance = {
            "low",
            "medium",
            "high"
        }

        for correlation in correlation_result["correlations"]:

            if not isinstance(correlation, dict):

                raise ValueError(
                    "Each correlation must be an object."
                )

            required_fields = [
                "elements",
                "relationship",
                "significance"
            ]

            for field in required_fields:

                if field not in correlation:

                    raise ValueError(
                        f"Correlation missing field: {field}"
                    )

            if not isinstance(
                correlation["elements"],
                list
            ):

                raise ValueError(
                    "correlation.elements must be a list."
                )

            if not isinstance(
                correlation["relationship"],
                str
            ):

                raise ValueError(
                    "correlation.relationship must be a string."
                )

            if correlation["significance"] not in allowed_significance:

                raise ValueError(
                    "Invalid correlation significance."
                )

    except Exception as e:

        print_failure(
            "Correlation validation failed."
        )

        print(f"Error: {e}")
        return


    # =====================================================
    # 18. UPDATE CASE WITH AGENT 4
    # =====================================================

    investigation_case[
        "correlation"
    ] = correlation_result


    # =====================================================
    # 19. AGENT 5 — DEEP INVESTIGATION
    # =====================================================

    def run_investigation():

        investigation_agent = (
            InvestigationAgent()
            .get_agent()
        )

        investigation_task = InvestigationTask(
            agent=investigation_agent,
            investigation_case=case.get_case()
        ).get_task()

        investigation_crew = Crew(
            agents=[investigation_agent],
            tasks=[investigation_task],
            verbose=False
        )

        return investigation_crew.kickoff()

    try:

        investigation_result_raw = run_with_progress(
            "Performing deep investigation",
            run_investigation
        )

    except Exception as e:

        print(f"\nError: {e}")
        return


    # =====================================================
    # 20. VALIDATE AGENT 5
    # =====================================================

    investigation_validator = InvestigationValidator()

    try:

        investigation_valid, investigation_result = (
            investigation_validator.validate(
                investigation_result_raw
            )
        )

    except Exception as e:

        print_failure(
            "Deep investigation validation failed."
        )

        print(f"Error: {e}")
        return


    if not investigation_valid:

        print_failure(
            "Deep investigation returned invalid output."
        )

        print(f"Error: {investigation_result}")
        return


    # =====================================================
    # 21. UPDATE CASE WITH AGENT 5
    # =====================================================

    investigation_case[
        "investigation"
    ] = investigation_result


    # =====================================================
    # 22. AGENT 6 — COUNTER-ANALYSIS
    # =====================================================

    def run_counter_analysis():

        counter_analysis_agent = (
            CounterAnalysisAgent()
            .get_agent()
        )

        counter_analysis_task = CounterAnalysisTask(
            agent=counter_analysis_agent,
            investigation_case=case.get_case()
        ).get_task()

        counter_analysis_crew = Crew(
            agents=[counter_analysis_agent],
            tasks=[counter_analysis_task],
            verbose=False
        )

        return counter_analysis_crew.kickoff()

    try:

        counter_analysis_result_raw = run_with_progress(
            "Performing counter-analysis",
            run_counter_analysis
        )

    except Exception as e:

        print(f"\nError: {e}")
        return


    # =====================================================
    # 23. VALIDATE AGENT 6
    # =====================================================

    counter_analysis_validator = (
        CounterAnalysisValidator()
    )

    try:

        counter_analysis_valid, counter_analysis_result = (
            counter_analysis_validator.validate(
                counter_analysis_result_raw
            )
        )

    except Exception as e:

        print_failure(
            "Counter-analysis validation failed."
        )

        print(f"Error: {e}")
        return


    if not counter_analysis_valid:

        print_failure(
            "Counter-analysis returned invalid output."
        )

        print(f"Error: {counter_analysis_result}")
        return


    # =====================================================
    # 24. UPDATE CASE WITH AGENT 6
    # =====================================================

    investigation_case[
        "counter_analysis"
    ] = counter_analysis_result


    # =====================================================
    # 25. AGENT 7 — FINAL VERDICT
    # =====================================================

    def run_verdict():

        verdict_agent = (
            FinalVerdictAgent()
            .get_agent()
        )

        verdict_task = FinalVerdictTask(
            agent=verdict_agent,
            investigation_case=case.get_case()
        ).get_task()

        verdict_crew = Crew(
            agents=[verdict_agent],
            tasks=[verdict_task],
            verbose=False
        )

        return verdict_crew.kickoff()

    try:

        verdict_result_raw = run_with_progress(
            "Determining final security verdict",
            run_verdict
        )

    except Exception as e:

        print(f"\nError: {e}")
        return


    # =====================================================
    # 26. VALIDATE AGENT 7
    # =====================================================

    verdict_validator = VerdictValidator()

    try:

        verdict_valid, verdict_result = (
            verdict_validator.validate(
                verdict_result_raw
            )
        )

    except Exception as e:

        print_failure(
            "Final verdict validation failed."
        )

        print(f"Error: {e}")
        return


    if not verdict_valid:

        print_failure(
            "Final verdict returned invalid output."
        )

        print(f"Error: {verdict_result}")
        return


    # =====================================================
    # 27. UPDATE CASE WITH AGENT 7
    # =====================================================

    investigation_case[
        "verdict"
    ] = verdict_result


    # =========================================================
    # HUMAN-READABLE INVESTIGATION REPORT
    # =========================================================

    print()

    print("=" * 70)
    print("                    INVESTIGATION REPORT")
    print("                       SENTINELCHAIN AI")
    print("=" * 70)

    # =========================================================
    # CASE INFORMATION
    # =========================================================

    print()
    print("-" * 70)
    print("CASE INFORMATION")
    print("-" * 70)

    alert_info = investigation_case.get(
        "alert",
        {}
    )

    rule_info = alert_info.get(
        "rule",
        {}
    )

    endpoint_info = investigation_case.get(
        "endpoint",
        {}
    )

    print(
        f"Case ID        : "
        f"{investigation_case.get('case_id', 'N/A')}"
    )

    print(
        f"Status         : "
        f"{investigation_case.get('status', 'N/A').upper()}"
    )

    print(
        f"Alert ID       : "
        f"{alert_info.get('alert_id', 'N/A')}"
    )

    print(
        f"Timestamp      : "
        f"{alert_info.get('timestamp', 'N/A')}"
    )

    print(
        f"Rule ID        : "
        f"{rule_info.get('id', 'N/A')}"
    )

    print(
        f"Rule Severity  : "
        f"{rule_info.get('level', 'N/A')}"
    )

    print(
        f"Rule            : "
        f"{rule_info.get('description', 'N/A')}"
    )

    # =========================================================
    # WHAT HAPPENED
    # =========================================================

    print()
    print("-" * 70)
    print("WHAT HAPPENED")
    print("-" * 70)

    print()

    print(
        f"{triage_result.get('summary', 'No summary available.')}"
    )

    # =========================================================
    # ENDPOINT INFORMATION
    # =========================================================

    print()
    print("-" * 70)
    print("ENDPOINT INFORMATION")
    print("-" * 70)

    print(
        f"Agent Name     : "
        f"{endpoint_info.get('agent_name', 'N/A')}"
    )

    print(
        f"Agent ID       : "
        f"{endpoint_info.get('agent_id', 'N/A')}"
    )

    print(
        f"Agent IP       : "
        f"{endpoint_info.get('agent_ip', 'N/A')}"
    )

    print(
        f"Hostname       : "
        f"{endpoint_info.get('hostname', 'N/A')}"
    )

    # =========================================================
    # NETWORK INFORMATION
    # =========================================================

    network_info = investigation_case.get(
        "network",
        {}
    )

    print()
    print("-" * 70)
    print("NETWORK INFORMATION")
    print("-" * 70)

    print(
        f"Source IP      : "
        f"{network_info.get('source_ip', 'N/A')}"
    )

    print(
        f"Source Port    : "
        f"{network_info.get('source_port', 'N/A')}"
    )

    print(
        f"Destination IP : "
        f"{network_info.get('destination_ip', 'N/A')}"
    )

    print(
        f"Protocol       : "
        f"{network_info.get('protocol', 'N/A')}"
    )

    # =========================================================
    # INITIAL TRIAGE
    # =========================================================

    print()
    print("-" * 70)
    print("INITIAL TRIAGE")
    print("-" * 70)

    print(
        f"Category       : "
        f"{triage_result.get('category', 'N/A').upper()}"
    )

    print(
        f"Priority       : "
        f"{triage_result.get('priority', 'N/A').upper()}"
    )

    print(
        f"Investigation  : "
        f"{'YES' if triage_result.get('investigation_required') else 'NO'}"
    )

    print()
    print("Summary:")
    print(
        f"  {triage_result.get('summary', 'N/A')}"
    )

    print()
    print("Reason:")
    print(
        f"  {triage_result.get('reason', 'N/A')}"
    )

    # =========================================================
    # EVIDENCE
    # =========================================================

    print()
    print("-" * 70)
    print("EVIDENCE ANALYSIS")
    print("-" * 70)

    print()
    print("Evidence Found:")

    evidence_found = evidence_result.get(
        "evidence_found",
        []
    )

    if evidence_found:

        for item in evidence_found:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • No evidence identified."
        )

    print()
    print("Evidence Missing:")

    evidence_missing = evidence_result.get(
        "evidence_missing",
        []
    )

    if evidence_missing:

        for item in evidence_missing:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • No major evidence gaps identified."
        )

    print()
    print("Observations:")

    observations = evidence_result.get(
        "observations",
        []
    )

    if observations:

        for item in observations:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • No additional observations."
        )

    # =========================================================
    # THREAT INTELLIGENCE
    # =========================================================

    print()
    print("-" * 70)
    print("THREAT INTELLIGENCE")
    print("-" * 70)

    indicators_checked = threat_intel_result.get(
        "indicators_checked",
        []
    )

    print()
    print("Indicators Checked:")

    if indicators_checked:

        for indicator in indicators_checked:

            if isinstance(indicator, dict):

                indicator_type = indicator.get(
                    "type",
                    "unknown"
                )

                indicator_value = indicator.get(
                    "value",
                    "unknown"
                )

                source = indicator.get(
                    "source",
                    "unknown"
                )

                result = indicator.get(
                    "result",
                    "unknown"
                )

                print(
                    f"  • {indicator_type.upper()}: "
                    f"{indicator_value}"
                )

                print(
                    f"    Source : {source}"
                )

                print(
                    f"    Result : {result}"
                )

            else:

                print(
                    f"  • {indicator}"
                )

    else:

        print(
            "  • No indicators were checked."
        )

    print()
    print("Threat Intelligence Findings:")

    threat_findings = threat_intel_result.get(
        "threat_intelligence",
        []
    )

    if threat_findings:

        for item in threat_findings:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • No significant threat intelligence findings."
        )

    print()
    print("Summary:")

    print(
        f"  {threat_intel_result.get('summary', 'N/A')}"
    )

    # =========================================================
    # CORRELATION
    # =========================================================

    print()
    print("-" * 70)
    print("CORRELATION ANALYSIS")
    print("-" * 70)

    correlations = correlation_result.get(
        "correlations",
        []
    )

    print()
    print("Correlations:")

    if correlations:

        for correlation in correlations:

            elements = correlation.get(
                "elements",
                []
            )

            relationship = correlation.get(
                "relationship",
                "N/A"
            )

            significance = correlation.get(
                "significance",
                "N/A"
            )

            print()
            print(
                f"  • Significance: "
                f"{significance.upper()}"
            )

            print(
                f"    Elements: "
                f"{', '.join(str(x) for x in elements)}"
            )

            print(
                f"    Relationship: "
                f"{relationship}"
            )

    else:

        print(
            "  • No meaningful correlations identified."
        )

    print()
    print("Supporting Evidence:")

    supporting_evidence = correlation_result.get(
        "supporting_evidence",
        []
    )

    if supporting_evidence:

        for item in supporting_evidence:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • None identified."
        )

    print()
    print("Contradicting Evidence:")

    contradicting_evidence = correlation_result.get(
        "contradicting_evidence",
        []
    )

    if contradicting_evidence:

        for item in contradicting_evidence:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • None identified."
        )

    print()
    print("Observed Patterns:")

    patterns = correlation_result.get(
        "patterns",
        []
    )

    if patterns:

        for item in patterns:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • No significant patterns identified."
        )

    print()
    print("Summary:")

    print(
        f"  {correlation_result.get('summary', 'N/A')}"
    )

    # =========================================================
    # DEEP INVESTIGATION
    # =========================================================

    print()
    print("-" * 70)
    print("DEEP INVESTIGATION")
    print("-" * 70)

    investigation_findings = investigation_result.get(
        "investigation_findings",
        []
    )

    print()
    print("Investigation Findings:")

    if investigation_findings:

        for finding in investigation_findings:

            finding_text = finding.get(
                "finding",
                "N/A"
            )

            finding_type = finding.get(
                "type",
                "unknown"
            )

            significance = finding.get(
                "significance",
                "unknown"
            )

            print()
            print(
                f"  • [{finding_type.upper()} | "
                f"{significance.upper()}]"
            )

            print(
                f"    {finding_text}"
            )

    else:

        print(
            "  • No investigation findings identified."
        )

    print()
    print("Activity Summary:")

    print(
        f"  {investigation_result.get('activity_summary', 'N/A')}"
    )

    print()
    print("Evidence Supporting Findings:")

    investigation_support = investigation_result.get(
        "evidence_supporting_findings",
        []
    )

    if investigation_support:

        for item in investigation_support:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • None identified."
        )

    print()
    print("Evidence Gaps:")

    investigation_gaps = investigation_result.get(
        "evidence_gaps",
        []
    )

    if investigation_gaps:

        for item in investigation_gaps:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • No major evidence gaps identified."
        )

    print()
    print("Recommended Investigation Next Steps:")

    next_steps = investigation_result.get(
        "investigation_next_steps",
        []
    )

    if next_steps:

        for item in next_steps:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • No additional steps recommended."
        )

    # =========================================================
    # COUNTER-ANALYSIS
    # =========================================================

    print()
    print("-" * 70)
    print("COUNTER-ANALYSIS")
    print("-" * 70)

    challenges = counter_analysis_result.get(
        "challenges",
        []
    )

    print()
    print("Challenges:")

    if challenges:

        for challenge in challenges:

            print()
            print(
                f"  • Strength: "
                f"{challenge.get('strength', 'unknown').upper()}"
            )

            print(
                f"    Finding Challenged:"
            )

            print(
                f"      "
                f"{challenge.get('finding_challenged', 'N/A')}"
            )

            print(
                f"    Challenge:"
            )

            print(
                f"      "
                f"{challenge.get('challenge', 'N/A')}"
            )

            print(
                f"    Alternative Explanation:"
            )

            print(
                f"      "
                f"{challenge.get('alternative_explanation', 'N/A')}"
            )

    else:

        print(
            "  • No significant challenges identified."
        )

    print()
    print("Assumptions Identified:")

    assumptions = counter_analysis_result.get(
        "assumptions_identified",
        []
    )

    if assumptions:

        for item in assumptions:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • None identified."
        )

    print()
    print("Supporting Factors:")

    supporting_factors = counter_analysis_result.get(
        "supporting_factors",
        []
    )

    if supporting_factors:

        for item in supporting_factors:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • None identified."
        )

    print()
    print("Uncertainties:")

    counter_uncertainties = counter_analysis_result.get(
        "uncertainties",
        []
    )

    if counter_uncertainties:

        for item in counter_uncertainties:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • None identified."
        )

    print()
    print("Recommended Verifications:")

    verifications = counter_analysis_result.get(
        "recommended_verifications",
        []
    )

    if verifications:

        for item in verifications:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • No additional verification recommended."
        )

    print()
    print("Counter-Analysis Summary:")

    print(
        f"  {counter_analysis_result.get('summary', 'N/A')}"
    )

    # =========================================================
    # FINAL ASSESSMENT
    # =========================================================

    print()
    print("=" * 70)
    print("                      FINAL ASSESSMENT")
    print("=" * 70)

    print()

    final_verdict = verdict_result.get(
        "verdict",
        "N/A"
    )

    final_confidence = verdict_result.get(
        "confidence",
        "N/A"
    )

    escalation = verdict_result.get(
        "recommended_escalation",
        False
    )

    print(
        f"Verdict        : "
        f"{final_verdict.upper()}"
    )

    print(
        f"Confidence     : "
        f"{final_confidence.upper()}"
    )

    print(
        f"Escalation     : "
        f"{'YES' if escalation else 'NO'}"
    )

    print()
    print("Summary:")

    print(
        f"  {verdict_result.get('summary', 'N/A')}"
    )

    print()
    print("Decision Reasoning:")

    reasoning = verdict_result.get(
        "reasoning",
        []
    )

    if reasoning:

        for item in reasoning:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • No reasoning provided."
        )

    print()
    print("Key Evidence:")

    key_evidence = verdict_result.get(
        "key_evidence",
        []
    )

    if key_evidence:

        for item in key_evidence:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • None identified."
        )

    print()
    print("Counter Evidence:")

    counter_evidence = verdict_result.get(
        "counter_evidence",
        []
    )

    if counter_evidence:

        for item in counter_evidence:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • None identified."
        )

    print()
    print("Uncertainties:")

    final_uncertainties = verdict_result.get(
        "uncertainties",
        []
    )

    if final_uncertainties:

        for item in final_uncertainties:

            print(
                f"  • {item}"
            )

    else:

        print(
            "  • None identified."
        )

    # =========================================================
    # COMPLETE
    # =========================================================

    print()
    print("=" * 70)
    print("                  SENTINELCHAIN COMPLETE")
    print("=" * 70)
    print()

    print(
        f"Case ID        : "
        f"{investigation_case['case_id']}"
    )

    print(
        f"Verdict        : "
        f"{verdict_result['verdict'].upper()}"
    )

    print(
        f"Confidence     : "
        f"{verdict_result['confidence'].upper()}"
    )

    print(
        f"Escalation     : "
        f"{'YES' if verdict_result['recommended_escalation'] else 'NO'}"
    )

    print()


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    main()