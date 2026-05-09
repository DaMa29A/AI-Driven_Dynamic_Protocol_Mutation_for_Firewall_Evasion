import json
import requests

def _strip_keys(obj):
    if isinstance(obj, dict):
        return {str(k).strip(): _strip_keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_keys(x) for x in obj]
    if isinstance(obj, str):
        return obj.strip()
    return obj


class LLMEvasionStrategyEngine:
    def __init__(self, ollama_url: str, model: str):
        self.ollama_url = ollama_url
        self.model = model
        

    def generate_strategy(self, baseline: dict, last_feedback: dict | None = None) -> dict:
        prompt = self._build_prompt(baseline, last_feedback)
        #print(prompt)

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.8,
                "top_p": 0.85,
                "repeat_penalty": 1.3,
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
        return self._validate_and_normalize(strategy)


    def _build_prompt(self, baseline: dict, last_feedback: dict | None) -> str:
        print("Last feedback: " + last_feedback)
        return f"""
Sei un Red Teamer.

Obiettivo:
Il firewall blocca User-Agent sospetti.
Proponi un nuovo User-Agent.

User-Agent precedente:
{last_feedback}

Vincoli obbligatori:
- Rispondi SOLO con JSON valido.
- Nessun markdown.
- Nessun commento.
- In 'reason' devi spiegarmi in modo esaustivo perchè hai scelto quei valori per la strategia.
- User-Agent DEVE essere una stringa.
- Usa un User-Agent completamente differente dal precedente.
- Alterna tra: browser desktop, browser mobile, client CLI (curl, wget, python)

Schema JSON obbligatorio:
{{
  "http": {{
    "method": "GET",
    "path": "string",
    "headers": {{
      "User-Agent": "string",
    }}
  }},
  "reason": "string"
}}
"""

    def _validate_and_normalize(self, strategy: dict) -> dict:
        strategy = _strip_keys(strategy)
        
        http = strategy.get("http")
        if not isinstance(http, dict):
            http = {}

        headers = http.get("headers")
        if not isinstance(headers, dict):
            headers = {}

        method = http.get("method", "GET")
        if not isinstance(method, str):
            method = "GET"

        method = method.strip().upper()
        if method not in {"GET", "HEAD"}:
            method = "GET"

        path = http.get("path", "/")
        if not isinstance(path, str):
            path = "/"

        path = path.strip()
        if not path.startswith("/"):
            path = "/" + path
        if path == "/":
            path = "/"

        user_agent = headers.get("User-Agent", "")
        if not isinstance(user_agent, str):
            user_agent = ""

        user_agent = user_agent.strip()

        reason = strategy.get("reason", "")
        if not isinstance(reason, str):
            reason = ""

        reason = reason.strip()

        return {
            "http": {
                "method": method,
                "path": path,
                "headers": {
                    "User-Agent": user_agent
                }
            },
            "reason": reason
        }
        
        
        
        

#     def _build_prompt(self, baseline: dict, last_feedback: dict | None) -> str:
#         return f"""
# Sei un red teamer.

# Obiettivo:
# Generare UNA nuova strategia JSON per testare traffico HTTP/TCP verso un target che usa firewall pfSense con Suricata.

# Baseline osservata:
# {json.dumps(baseline, indent=2)}

# Vincoli obbligatori:
# - Rispondi SOLO con JSON valido.
# - Nessun markdown.
# - Nessun commento.
# - In 'reason' devi spiegarmi in modo esaustivo perchè hai scelto quei valori per la strategia.
# - User-Agent DEVE essere una stringa.
# - Varia soprattutto User-Agent, ttl e tcp_window.

# Schema JSON obbligatorio:
# {{
#   "http": {{
#     "method": "GET",
#     "path": "string",
#     "headers": {{
#       "User-Agent": "string",
#     }}
#   }},
#   "packet": {{
#     "ttl": int,
#     "tcp_window": int
#   }},
#   "reason": "string"
# }}
# """

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