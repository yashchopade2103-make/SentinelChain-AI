from crewai import Agent, LLM


class CounterAnalysisAgent:
    def __init__(self):
        self.llm = LLM(
            model="ollama/qwen3:8b",
            base_url="http://localhost:11434",
            temperature=0.1
        )

        self.agent = Agent(
            role="SOC Counter-Analysis Analyst",

            goal=(
                "Challenge the findings and conclusions produced during "
                "the security investigation. Identify weak assumptions, "
                "alternative explanations, contradictions, uncertainties, "
                "and evidence that should be verified before a final "
                "investigation verdict is made."
            ),

            backstory=(
                "You are an experienced SOC analyst specializing in "
                "counter-analysis and investigative validation. Your job "
                "is to critically examine an investigation rather than "
                "simply agree with previous analysts. You look for "
                "unsupported conclusions, weak assumptions, alternative "
                "benign or malicious explanations, contradictions, and "
                "important uncertainties. You distinguish confirmed "
                "evidence from reasonable inferences and possibilities. "
                "You understand that missing evidence does not prove that "
                "an event did not occur. You never invent evidence or "
                "claim that a hypothesis is confirmed without sufficient "
                "support."
            ),

            llm=self.llm,
            verbose=True
        )

    def get_agent(self):
        return self.agent