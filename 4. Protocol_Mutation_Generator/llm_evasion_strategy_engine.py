import json
import re
import requests

class LLMEvasionStrategyEngine:
    def __init__(self, baseline_json_path, model="llama3.1:8b", ollama_url="http://localhost:11434/api/generate"):
        self.model = model
        #self.ollama_url = ollama_url
        self.ollama_url="http://192.168.98.1:11434/api/generate"
        self.history = []
        
        with open(baseline_json_path, "r") as f:
            self.baseline = json.load(f)

    def _build_prompt(self):
        #protocols = ["TCP", "HTTP", "TLS"]
        protocols = ["TCP"]

        total_packets = self.baseline.get("total_packets", "N/A")
        min_dim_packet = self.baseline.get("features", {}).get("packet_size", {}).get("stats", {}).get("min")
        max_dim_packet = self.baseline.get("features", {}).get("packet_size", {}).get("stats", {}).get("max")
        min_ttl = self.baseline.get("features", {}).get("ttl", {}).get("stats", {}).get("min")
        max_ttl = self.baseline.get("features", {}).get("ttl", {}).get("stats", {}).get("max")
        min_tcp_win_size = self.baseline.get("features", {}).get("tcp_window_size", {}).get("stats", {}).get("min")
        max_tcp_win_size = self.baseline.get("features", {}).get("tcp_window_size", {}).get("stats", {}).get("max")

        # Level 3
        #fields_ip_to_mutate = ["ttl", "tos", "flags", "options", "frag", "id"]
        fields_ip_to_mutate = ["ttl"]
        # Level 4
        #fields_tcp_to_mutate = ["seq", "ack", "window", "flags", "options"]
        fields_tcp_to_mutate = ["window"]
        # Level 7
        fields_http_to_mutate = ["User-Agent", "Accept", "Accept-Language", "Host", "Connection", "Content-Length", "Cookie"]
        
        prompt = (
            'You are a cybersecurity expert (Red Teamer). \n'
            'Objective: '
            'Analyze a baseline profile of legitimate network traffic '
            'eand generate ONE realistic and technically valid strategy to evade a pfSense firewall running Suricata/Snort '
            'with public rule sets (Emerging Threats).\n\n'

            'Baseline traffic profile to analyze. All generated mutations must be consistent with these observed values:\n'
            f'"total_packets": {total_packets}\n'
            f'"min_dim_packet": {min_dim_packet}\n'
            f'"max_dim_packet": {max_dim_packet}\n'
            f'"min_ttl": {min_ttl}\n'
            f'"max_ttl": {max_ttl}\n'
            f'"min_tcp_win_size": {min_tcp_win_size}\n'
            f'"max_tcp_win_size": {max_tcp_win_size}\n\n'

            'Allowed protocols:\n'
            f'{protocols}\n\n'

            'You are ONLY allowed to use the fields listed above. Do not introduce any additional fields.\n'
            'IP fields:\n'
            f'{fields_ip_to_mutate}\n'
            'TCP fields:\n'
            f'{fields_tcp_to_mutate}\n\n'

            'Mandatory constraints:\n'
            '1. All mutations must be protocol-compliant.\n'
            '2. You may use multiple packets to implement the strategy..\n'
            '3. You must specify all packet fields required to build the packet using Scapy.\n'
            '4. DO NOT include source IP, destination IP, source port, or destination port.\n'
            '5. Use prefixes: "IP.xxx", "TCP.xxx".\n'
            '7. You must respond ONLY with valid JSON.\n'
            '8. Do not add any text before or after the JSON output.\n\n'
            
            'Required JSON schema that you MUST always follow:\n'
            '{\n'       
            '    "protocol": "TCP|HTTP|TLS",\n'
            '    "strategy_name": "Short descriptive name summarizing the strategy",\n'
            '    "reasoning": "Technical explanation of why this strategy could be effective and how it aligns with the baseline data",\n'
            '    "packet_count": int,\n'
            '    "packets": [\n'
            '        {\n'
            '             ...\n'
            '        },\n'
            '        ...\n'
            '     ]\n' 
            '}\n'               
        )
        return prompt

    def get_next_mutation(self):
        prompt = self._build_prompt()
        print(f"\n[LLM - {self.model}] - Prompt inviato:\n{prompt}")

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.3
            }
        }
        
        try:
            response = requests.post(self.ollama_url, json=payload)
            response.raise_for_status() 
            
            # Ollama restituisce il testo dentro la chiave "response"
            response_text = response.json()["response"]
            return response_text
          
        except Exception as e:
            print(f"[!] Errore di comunicazione con Ollama: {e}")
            return None

    # def update_history(self, value, reward):
    #     """
    #     Registra il segnale di rinforzo ricevuto per raffinare le strategie future[cite: 134, 180].
    #     """
    #     self.history.append({"value": value, "reward": reward})