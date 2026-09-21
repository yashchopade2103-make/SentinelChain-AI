from crewai import Agent, LLM


class InvestigationAgent:
    def __init__(self):
        self.llm = LLM(
            model="ollama/qwen3:8b",
            base_url="http://localhost:11434",
            temperature=0.1
        )

        self.agent = Agent(
            role="SOC Investigation Analyst",
            goal=(
                "Perform a deeper investigation of a security case using "
                "the alert, triage findings, evidence analysis, threat "
                "intelligence, and correlation results already collected. "
                "Reconstruct the observed activity, identify important "
                "findings, distinguish confirmed facts from reasonable "
                "inferences and uncertainty, identify evidence gaps, and "
                "determine what should be investigated next without making "
                "the final verdict."
            ),
            backstory=(
                "You are an experienced SOC investigation analyst. You "
                "analyze security cases by bringing together findings from "
                "multiple investigation stages. You reconstruct activity "
                "from the available evidence and carefully distinguish "
                "confirmed facts from reasonable security inferences. "
                "You understand that missing evidence does not prove that "
                "an event did not occur. You never invent evidence, events, "
                "IOCs, users, processes, timestamps, or threat intelligence."
            ),
            llm=self.llm,
            verbose=True
        )

    def get_agent(self):
        return self.agent