from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
import json


class LLMEvasionStrategyEngine:
    def __init__(self, ollama_url: str, model: str):
        self.llm = ChatOllama(
            model=model,
            base_url=ollama_url,
            temperature=0.9,
            top_p=0.95,
            repeat_penalty=1.15,
        )

        self.history = []
        self.used_user_agents = set()
        self.used_TTL = set()

    def generate_strategy(self, baseline: dict | None = None, last_feedback: dict | None = None) -> str:
        used_list = "\n".join(
            f"- {ua}" for ua in sorted(self.used_user_agents)
        )
        #print(f"Used User-Agents:\n{used_list if used_list else '(none)'}")

        messages = [
            SystemMessage(content=(
                "You are a Red Teamer.\n\n"
                "The firewall blocks suspicious User-Agent strings.\n\n"
                "Objective:\n"
                "Generate a single realistic HTTP User-Agent.\n\n"
                "Constraints:\n"
                "- Return ONLY the User-Agent string\n"
                "- No explanation\n"
                "- No markdown\n"
                "- One line only\n"
            )),
            *self.history[-20:],
            HumanMessage(content=(
                "Already used User-Agent strings. Do NOT repeat them:\n"
                f"{used_list if used_list else '(none)'}\n\n"
                "Generate a new realistic HTTP User-Agent different from all the ones above."
            ))
        ]

        result = self.llm.invoke(messages)
        #ua = self._validate_and_normalize(result.content)
        ua = result.content

        key = ua.lower()

        if key in self.used_user_agents:
            raise ValueError(f"Duplicate User-Agent generated: {ua}")

        self.used_user_agents.add(key)

        self.history.append(HumanMessage(content="Generate a new User-Agent."))
        self.history.append(AIMessage(content=ua))

        return ua

    def _validate_and_normalize(self, text: str) -> str:
        pass
    
    def generate_tcp_strategy(self, baseline: dict | None = None, last_feedback: dict | None = None) -> str:
        """
        Genera una strategia di mutazione decidendo dinamicamente se alterare TTL o Window Size.
        Ritorna un dizionario parsato dal JSON dell'LLM.
        """
        baseline_info = json.dumps(baseline) if baseline else "Unknown (No baseline provided)"

        feedback_info = "First attempt (No previous feedback)."
        if last_feedback:
            feedback_info = (
                f"Verdict: {last_feedback.get('verdict')}, "
                f"Reward: {last_feedback.get('reward')}, "
                f"Reason: {last_feedback.get('reason')}"
            )

        # 2. Costruiamo il prompt
        messages = [
            SystemMessage(content=(
                "You are an expert Red Teamer.\n\n"
                "Your objective is to generate dynamic protocol mutations to evade detection.\n"
                "You can mutate the following TCP/IP fields:\n"
                "- 'TTL'\n"
                "- 'WindowSize'\n\n"
                "Constraints:\n"
                "1. Output ONLY a valid JSON object. No markdown, no intro, no outro.\n"
                "2. Use this exact schema:\n"
                "{\n"
                '  "field_to_mutate": "TTL" or "WindowSize",\n'
                '  "new_value": <integer>,\n'
                '  "reasoning": "<short chain-of-thought explanation of why you chose this>"\n'
                "}\n"
            )),
            *self.history[-10:], # Teniamo gli ultimi 10 messaggi di storia
            HumanMessage(content=(
                f"BASELINE TRAFFIC PROFILE:\n{baseline_info}\n\n"
                f"LAST DROP FEEDBACK:\n{feedback_info}\n\n"
                "Based on the feedback, decide whether to mutate 'TTL' or 'WindowSize'. "
                "Generate the JSON for the next mutation strategy."
            ))
        ]

        # 3. Chiamata all'LLM
        result = self.llm.invoke(messages)
        raw_output = result.content.strip()

        # Rimuoviamo eventuali blocchi markdown (es. ```json ... ```) se l'LLM disubbidisce
        if raw_output.startswith("```json"):
            raw_output = raw_output[7:-3].strip()
        elif raw_output.startswith("```"):
            raw_output = raw_output[3:-3].strip()

        # 4. Parsing e salvataggio
        try:
            strategy_dict = json.loads(raw_output)
            
            # Salviamo nella cronologia per il prossimo ciclo
            self.history.append(HumanMessage(content="Generate a new TCP mutation strategy."))
            self.history.append(AIMessage(content=raw_output))
            
            return strategy_dict
            
        except json.JSONDecodeError:
            print(f"Error decoding JSON from LLM: {raw_output}")
            # Fallback o gestione errore
            return {"field_to_mutate": "TTL", "new_value": 64, "reasoning": "Fallback due to JSON error"}
        
        