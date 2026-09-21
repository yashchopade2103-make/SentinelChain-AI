from crewai import Agent, LLM


class AlertTriageAgent:
    """
    Agent 1 — Alert Triage Agent

    Performs the initial triage of a security alert.
    """

    def __init__(self):
        # Local LLM running through Ollama
        self.llm = LLM(
            model="ollama/qwen3:8b",
            base_url="http://localhost:11434",
            temperature=0.1
        )

        # CrewAI Agent
        self.agent = Agent(
            role="SOC Alert Triage Analyst",

            goal=(
                "Analyze a security alert and perform initial SOC triage. "
                "Determine what happened, categorize the event, assign an "
                "initial priority, and decide whether further investigation "
                "is required."
            ),

            backstory=(
                "You are a Level 1 SOC analyst responsible for the initial "
                "triage of security alerts. You carefully examine the "
                "available evidence and make a cautious initial assessment. "
                "You never invent information that is not present in the "
                "provided alert."
            ),

            llm=self.llm,
            verbose=True
        )

    def get_agent(self):
        """Return the CrewAI Agent instance."""
        return self.agent 