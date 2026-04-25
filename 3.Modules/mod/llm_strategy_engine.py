import json
import requests


class LLMEvasionStrategyEngine:
    def __init__(self, ollama_url: str, model: str):
        self.ollama_url = ollama_url
        self.model = model

    def generate_strategy(self, baseline: dict, last_feedback: dict | None = None) -> dict:
        prompt = self._build_prompt(baseline, last_feedback)
        print(prompt)

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.5,
                "top_p": 0.9,
                "repeat_penalty": 1.2
            }
        }

        response = requests.post(
            self.ollama_url,
            json=payload,
            timeout=300
        )
        response.raise_for_status()

        data = response.json()
        raw_text = data.get("response", "")

        strategy = json.loads(raw_text)
        #return self._validate_and_normalize(strategy)
        return strategy

    def _build_prompt(self, baseline: dict, last_feedback: dict | None) -> str:
        return f"""
Sei un red teamer.

Obiettivo:
Generare UNA nuova strategia JSON per testare traffico HTTP/TCP verso un target che usa firewall pfSense.

Baseline osservata:
{json.dumps(baseline, indent=2)}

Ultimo feedback:
{json.dumps(last_feedback, indent=2) if last_feedback else "Nessun feedback precedente"}

Vincoli obbligatori:
- Rispondi SOLO con JSON valido.
- Nessun markdown.
- Nessun commento.
- Se è presente "Ultimo feedback" genera una NUOVA strategia diversa.
- Agisci soprattutto su User-Agent, TTL e TCP_WINDOWS.
- In 'reason' devi spiegarmi perchè hai scelto quei valori.

Schema JSON obbligatorio:
{{
  "strategy_id": "string",
  "http": {{
    "method": "GET",
    "path": "string",
    "headers": {{
      "User-Agent": "string",
    }}
  }},
  "packet": {{
    "ttl": int,
    "tcp_window": int
  }},
  "reason": "string"
}}
"""

    # def _validate_and_normalize(self, strategy: dict) -> dict:
    #     http = strategy.get("http", {})
    #     packet = strategy.get("packet", {})
    #     headers = http.get("headers", {})

    #     method = http.get("method", "GET").upper()
    #     if method not in {"GET", "HEAD"}:
    #         method = "GET"

    #     path = http.get("path", "/mfolder/index.html")
    #     if not isinstance(path, str) or not path.startswith("/mfolder/"):
    #         path = "/mfolder/index.html"

    #     user_agent = headers.get("User-Agent")
    #     if not isinstance(user_agent, str) or not user_agent.strip():
    #         user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

    #     ttl = int(packet.get("ttl", 64))
    #     if ttl < 32 or ttl > 128:
    #         ttl = 64

    #     tcp_window = int(packet.get("tcp_window", 64240))
    #     if tcp_window < 1024 or tcp_window > 65535:
    #         tcp_window = 64240

    #     return {
    #         "strategy_id": strategy.get("strategy_id", "strategy_ollama"),
    #         "http": {
    #             "method": method,
    #             "path": path,
    #             "headers": {
    #                 "User-Agent": user_agent,
    #             }
    #         },
    #         "packet": {
    #             "ttl": ttl,
    #             "tcp_window": tcp_window
    #         },
    #         "reason": strategy.get("reason", "")
    #     }