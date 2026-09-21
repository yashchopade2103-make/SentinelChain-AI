from crewai import Agent, LLM


class EvidenceAnalysisAgent:
    """
    Agent 2 — Evidence Analysis Agent

    Examines the available evidence in an Investigation Case,
    identifies important evidence, identifies missing evidence,
    and produces factual observations.
    """

    def __init__(self):
        self.llm = LLM(
            model="ollama/qwen3:8b",
            base_url="http://localhost:11434",
            temperature=0.1
        )

        self.agent = Agent(
            role="SOC Evidence Analysis Analyst",

            goal=(
                "Analyze the evidence available in a security investigation "
                "case. Identify important evidence that is present, identify "
                "important evidence that is missing, and produce factual "
                "observations that can support further investigation."
            ),

            backstory=(
                "You are a SOC analyst specializing in evidence analysis. "
                "You carefully examine security alerts, endpoint information, "
                "network information, user activity, process information, "
                "authentication data, logs, and previous triage findings. "
                "You distinguish between confirmed evidence and assumptions. "
                "You never invent evidence that is not present in the case."
            ),

            llm=self.llm,
            verbose=True
        )

    def get_agent(self):
        """Return the CrewAI Agent instance."""
        return self.agent