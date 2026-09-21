from crewai import Agent, LLM


class FinalVerdictAgent:

    def __init__(self):
        self.llm = LLM(
            model="ollama/qwen3:8b",
            base_url="http://localhost:11434",
            temperature=0.1
        )

        self.agent = Agent(
            role="SOC Final Verdict Analyst",

            goal=(
                "Make a careful final security assessment of an investigation "
                "case using all evidence and analysis collected by the previous "
                "investigation stages. Weigh confirmed evidence, reasonable "
                "inferences, threat intelligence, correlations, investigation "
                "findings, counter-analysis, and uncertainties before reaching "
                "a final verdict."
            ),

            backstory=(
                "You are a senior SOC analyst responsible for the final "
                "assessment of investigated security alerts. You do not simply "
                "agree with previous analysts. You weigh evidence objectively, "
                "consider alternative explanations, recognize uncertainty, "
                "and distinguish confirmed facts from inference. You understand "
                "that missing evidence does not prove that an event did not "
                "occur. You never invent evidence or claim that an unverified "
                "hypothesis is confirmed."
            ),

            llm=self.llm,
            verbose=True
        )

    def get_agent(self):
        return self.agent