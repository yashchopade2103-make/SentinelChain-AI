import os

from dotenv import load_dotenv
from crewai import Agent, LLM

from tools.ioc_extractor import IOCExtractor
from tools.abuseipdb_lookup import AbuseIPDBLookup


class ThreatIntelligenceAgent:
    """
    Agent 3 — Threat Intelligence Agent

    Uses deterministic tools to extract indicators and enrich
    IP addresses with AbuseIPDB threat-intelligence data.
    """

    def __init__(self):

        load_dotenv()

        api_key = os.getenv("ABUSEIPDB_API_KEY")

        if not api_key:
            raise ValueError(
                "ABUSEIPDB_API_KEY was not found in environment variables."
            )

        # Threat intelligence tools
        self.ioc_extractor = IOCExtractor
        self.abuseipdb = AbuseIPDBLookup(api_key)

        # Local LLM
        self.llm = LLM(
            model="ollama/qwen3:8b",
            base_url="http://localhost:11434",
            temperature=0.1
        )

        self.agent = Agent(
            role="SOC Threat Intelligence Analyst",

            goal=(
                "Analyze indicators of compromise present in an investigation "
                "case and interpret threat-intelligence evidence obtained "
                "from authorized tools. Determine whether available "
                "intelligence increases or decreases the suspicion "
                "associated with an indicator."
            ),

            backstory=(
                "You are a SOC analyst specializing in threat intelligence. "
                "You examine IP addresses, domains, URLs, file hashes, and "
                "other indicators using reliable threat-intelligence evidence. "
                "You carefully distinguish verified intelligence from "
                "assumptions. You never invent indicators, reputation data, "
                "or threat-intelligence results that are not provided."
            ),

            tools=[],

            llm=self.llm,
            verbose=True
        )

    def get_agent(self):
        return self.agent