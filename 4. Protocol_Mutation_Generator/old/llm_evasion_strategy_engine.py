from __future__ import annotations
import json
import re
import subprocess
from dataclasses import asdict
from typing import Any, Dict, List, Optional
from utils import json_to_string, load_json
from llm.llm_config import StrategyInput, SafeStrategyOutput, DEFAULT_MODEL, BASELINE_PATH

class LLMSafeStrategyEngine:
    def __init__(self, model: str ) -> None:
        self.model = model

    def build_prompt(self, baseline_profile: Dict[str, Any], last_failure: Dict[str, Any], protocol_scope: Optional[List[str]] = None) -> str:
        protocol_scope = protocol_scope or ["tcp", "http", "tls"]

        prompt = f"""
        Sei un Red Teamer.
        Il tuo obiettivo è analizzare un baseline profile di traffico legittimo, l'ultimo fallimento osservato durante un test (se presente),
        e generare UNA sola strategia tecnica mirata per evadere un firewall pfSense con Suricata/Snort con regole pubbliche (Emerging Threats).

        Vincoli obbligatori:
        1. Le mutazioni devono essere conformi al protocollo.
        2. Devi rispondere ESCLUSIVAMENTE con JSON valido.
        3. Non aggiungere testo prima o dopo il JSON.
        4. Non usare markdown.
        5. Non usare commenti.
        6. Devi darmi tutti i campi del pacchetto o dei pacchetti da costruire con Scapy.
        7. In mutation

        Puoi agire solo su questi protocolli:
        {json.dumps(protocol_scope, ensure_ascii=False)}


        Schema JSON obbligatorio:
        "protocol": "TCP|HTTP|TLS",
        "strategy_name": Nome descrittivo della strategia (string),
        "reasoning": Breve spiegazione tecnica del perchè questa strategia potrebbe funzionare (string),
        "packet_count": Numero di pacchetti da inviare con questa strategia (int),
        "packets": [
            
        ]
        
        
        "mutations": [
            "field": "campo consentito",
            "action": "set|replace|remove",
            "value": number or string 
        ]
        

        Baseline profile da analizzare bene:
        {json_to_string(baseline_profile)}

        Ultimo fallimento osservato:
        {json_to_string(last_failure)}  
        """

        return prompt

    def _run_ollama(self, prompt: str) -> str:
        try:
            result = subprocess.run(
                ["ollama", "run", self.model],
                input=prompt,
                text=True,
                capture_output=True,
                check=True,
                encoding="utf-8",
            )
            return result.stdout.strip()
        except FileNotFoundError as exc:
            raise RuntimeError(
                "Ollama non trovato. Verifica che sia installato e nel PATH."
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"Errore eseguendo Ollama: {exc.stderr.strip() or exc}"
            ) from exc

    @staticmethod
    def _extract_json(text: str) -> Dict[str, Any]:
        text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise ValueError("Nessun JSON valido trovato nell'output del modello.")

        candidate = match.group(0)
        return json.loads(candidate)
    

    def parse_strategy_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Estrae un JSON pulito dall'output raw del modello e mantiene solo:
        - target_layer
        - protocol
        - strategy_name
        - reasoning
        - mutations
        """

        if not raw_output or not isinstance(raw_output, str):
            return {
                "target_layer": "unknown",
                "protocol": "unknown",
                "strategy_name": "invalid_output",
                "reasoning": "",
                "mutations": []
            }

        text = raw_output.strip()

        # Rimuove eventuali code fences markdown
        text = re.sub(r"```json", "", text, flags=re.IGNORECASE)
        text = re.sub(r"```", "", text)

        # Prova prima il parser standard già presente
        try:
            data = self._extract_json(text)
        except Exception:
            return {
                "target_layer": "unknown",
                "protocol": "unknown",
                "strategy_name": "invalid_output",
                "reasoning": "",
                "mutations": []
            }

        # Estrazione campi base
        clean = {
            "target_layer": str(data.get("target_layer", "unknown")).strip(),
            "protocol": str(data.get("protocol", "unknown")).strip(),
            "strategy_name": str(data.get("strategy_name", "unknown")).strip(),
            "reasoning": str(data.get("reasoning", "")).strip(),
            "mutations": data.get("mutations", []),
        }

        # Normalizzazione stringhe vuote / null-like
        for key in ["target_layer", "protocol", "strategy_name"]:
            val = clean[key]
            if not val or val.lower() in {"null", "none", "undefined"}:
                clean[key] = "unknown"

        # Uniforma maiuscole/minuscole
        clean["target_layer"] = clean["target_layer"].upper()
        clean["protocol"] = clean["protocol"].upper()

        # Validazione minima mutations
        if not isinstance(clean["mutations"], list):
            clean["mutations"] = []

        normalized_mutations = []
        for m in clean["mutations"]:
            if not isinstance(m, dict):
                continue

            normalized_mutations.append({
                "field": str(m.get("field", "")).strip(),
                "action": str(m.get("action", "")).strip(),
                "value": str(m.get("value", "")).strip(),
            })

        clean["mutations"] = normalized_mutations

        return clean

    def generate_strategy(self, baseline_profile: Dict[str, Any], last_failure: Dict[str, Any], protocol_scope: Optional[List[str]] = None,) -> SafeStrategyOutput:
        prompt = self.build_prompt(
            baseline_profile=baseline_profile,
            last_failure=last_failure,
            protocol_scope=protocol_scope,
        )

        print ("Prompt generato per il modello:")
        print(prompt)

        raw_output = self._run_ollama(prompt)

        parsed = self.parse_strategy_output(raw_output)

        return SafeStrategyOutput(
            summary="",
            observations=[],
            allowed_actions=[],
            forbidden_actions=[],
            next_test_plan=[],
            raw_model_output=parsed,
        )


def main() -> None:
    baseline = load_json(BASELINE_PATH)
    #print(baseline["total_packets"])
    engine = LLMSafeStrategyEngine(model=DEFAULT_MODEL)
    strategy = engine.generate_strategy(baseline_profile=baseline, last_failure={}, protocol_scope=["tcp"])
    print("Strategia generata:")
    print(strategy)

if __name__ == "__main__":
    main()