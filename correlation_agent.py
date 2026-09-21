from crewai import Agent, LLM


class CorrelationAgent:
    def __init__(self):
        self.llm = LLM(
            model="ollama/qwen3:8b",
            base_url="http://localhost:11434",
            temperature=0.1
        )

        self.agent = Agent(
            role="SOC Correlation Analyst",
            goal=(
                "Analyze the information already collected in a security "
                "investigation case and identify meaningful relationships "
                "between the alert, evidence, triage findings, and threat "
                "intelligence. Identify supporting evidence, contradicting "
                "evidence, and observable patterns without making a final "
                "verdict."
            ),
            backstory=(
                "You are a SOC analyst specializing in security event "
                "correlation. You examine information collected from "
                "previous investigation stages and determine how different "
                "pieces of evidence relate to one another. You carefully "
                "distinguish confirmed relationships from assumptions. "
                "You never invent evidence or information that is not "
                "present in the investigation case."
            ),
            llm=self.llm,
            verbose=True
        )

    def get_agent(self):
        return self.agent