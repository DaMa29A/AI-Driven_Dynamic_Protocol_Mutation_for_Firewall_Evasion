from __future__ import annotations
import json
import re
import subprocess
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


#DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_MODEL = "llama3.2:3b"

@dataclass
class StrategyInput:
    baseline_profile: Dict[str, Any]
    last_failure: Dict[str, Any]


@dataclass
class SafeStrategyOutput:
    summary: str
    observations: List[str]
    allowed_actions: List[str]
    forbidden_actions: List[str]
    next_test_plan: Dict[str, Any]
    raw_model_output: str


class LLMSafeStrategyEngine:
    def __init__(self, model: str = DEFAULT_MODEL, ollama_bin: str = "ollama") -> None:
        self.model = model
        self.ollama_bin = ollama_bin

    def build_prompt(
        self,
        baseline_profile: Dict[str, Any],
        last_failure: Dict[str, Any],
        protocol_scope: Optional[List[str]] = None,
    ) -> str:
        scope = protocol_scope or ["tcp", "http", "tls"]

        system_prompt = (
            "Sei un Red Teamer."
            "Il tuo obiettivo è analizzare un baseline profile di traffico legittimo, "
            "l'ultimo fallimento osservato durante un test (se presente), "
            "e generare una singola strategia tecnica mirata per evadere un firewall pfSense. \n\n"

            "DEVI rispondere esclusivamente con un file JSON valido.\n"
            "Usa ESATTAMENTE questo schema come esempio, adattandolo alla tua strategia: \n"
            "{\n"
            '  "target_layer": "string",\n'
            '  "protocol": "string",\n'
            '  "strategy_name": "string",\n'
            '  "reasoning": ""string, \n'
            '  "mutations": [\n'
            "      {\n"
            '        "field": "string",\n'
            '        "action": "string",\n'
            '        "value": "string",\n'
            "      }, ...\n"
            "  ]\n"
            "}\n"
        )

        user_prompt = (
            "Le mutazioni devono essere conforme al protocollo. \n"
            f"Baseline profile:\n{json.dumps(baseline_profile, indent=2, ensure_ascii=False)}\n\n"
            f"Ultimo fallimento osservato:\n{json.dumps(last_failure, indent=2, ensure_ascii=False)}\n\n"
        )

        return f"{system_prompt}\n\n{user_prompt}"

    def _run_ollama(self, prompt: str) -> str:
        try:
            result = subprocess.run(
                [self.ollama_bin, "run", self.model],
                input=prompt,
                text=True,
                capture_output=True,
                check=True,
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
        """
        Try direct JSON parse first; fall back to extracting the first JSON object.
        """
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

    @staticmethod
    def _sanitize_output(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove unsafe content if the model drifts.
        """
        forbidden_patterns = [
            r"\bbypass\b",
            r"\bevad",
            r"\bobfus",
            r"\bstealth\b",
            r"\bmasquerad",
            r"\bmimic\b.+\btrusted\b",
            r"\blook like benign traffic\b",
            r"\bavoid detection\b",
            r"\bdisable logging\b",
        ]

        def contains_forbidden(value: Any) -> bool:
            if isinstance(value, str):
                lowered = value.lower()
                return any(re.search(p, lowered) for p in forbidden_patterns)
            if isinstance(value, list):
                return any(contains_forbidden(v) for v in value)
            if isinstance(value, dict):
                return any(contains_forbidden(v) for v in value.values())
            return False

        if contains_forbidden(data):
            return {
                "summary": (
                    "L'output del modello conteneva suggerimenti non ammessi. "
                    "È stato sostituito con una risposta sicura."
                ),
                "observations": [
                    "Il baseline profile può essere usato per validazione di robustezza.",
                    "L'ultimo fallimento va trattato come segnale per affinare i casi di test, non per aggirare controlli.",
                ],
                "allowed_actions": [
                    "variare campi entro limiti conformi al protocollo",
                    "verificare compatibilità e logging",
                    "misurare risposta del sistema a input leciti ma diversi",
                ],
                "forbidden_actions": [
                    "proporre evasione o bypass",
                    "far sembrare traffico ostile come benigno",
                    "ridurre la visibilità dei controlli difensivi",
                ],
                "next_test_plan": {
                    "goal": "verificare robustezza del parsing e della telemetria difensiva",
                    "protocols": ["tcp", "http"],
                    "candidate_variations": [
                        {
                            "field": "HTTP User-Agent",
                            "reason": "testare diversità lecita dei client",
                            "constraint": "usare solo user-agent reali e non ingannevoli nel contesto di test",
                            "example_value": "curl/8.5.0",
                        },
                        {
                            "field": "TCP window size",
                            "reason": "testare tolleranza a variazioni comuni dello stack",
                            "constraint": "restare in valori validi e coerenti con lo stack",
                            "example_value": "64240",
                        },
                    ],
                    "validation_checks": [
                        "il protocollo resta valido",
                        "i log vengono generati correttamente",
                        "la telemetria distingue le varianti senza falsi negativi evidenti",
                    ],
                },
            }

        return data

    def generate_strategy(
        self,
        baseline_profile: Dict[str, Any],
        last_failure: Dict[str, Any],
        test_objective: str = "authorized defensive resilience testing",
        protocol_scope: Optional[List[str]] = None,
    ) -> SafeStrategyOutput:
        prompt = self.build_prompt(
            baseline_profile=baseline_profile,
            last_failure=last_failure,
            test_objective=test_objective,
            protocol_scope=protocol_scope,
        )

        raw_output = self._run_ollama(prompt)
        parsed = self._extract_json(raw_output)
        safe = self._sanitize_output(parsed)

        return SafeStrategyOutput(
            summary=str(safe.get("summary", "")),
            observations=list(safe.get("observations", [])),
            allowed_actions=list(safe.get("allowed_actions", [])),
            forbidden_actions=list(safe.get("forbidden_actions", [])),
            next_test_plan=dict(safe.get("next_test_plan", {})),
            raw_model_output=raw_output,
        )


def main() -> None:
    example_baseline = {
        "input_file": "baseline_capture.pcap",
        "total_packets": 1200,
        "features": {
            "packet_size": {
                "stats": {"mean": 512.4, "min": 60, "max": 1514},
                "top_values": [[60, 120], [1514, 88], [540, 41]],
            },
            "ttl": {
                "stats": {"mean": 63.8, "min": 61, "max": 64},
                "top_values": [[64, 950], [63, 210], [62, 40]],
            },
            "tcp_window_size": {
                "stats": {"mean": 64240, "min": 8192, "max": 65535},
                "top_values": [[64240, 500], [65535, 230]],
            },
        },
    }

    # example_last_failure = {
    #     "timestamp": "2026-04-13T18:00:00",
    #     "protocol": "http",
    #     "result": "blocked_or_rejected",
    #     "response_type": "tcp_rst",
    #     "notes": "request variant rejected during controlled lab test",
    # }

    engine = LLMSafeStrategyEngine(model="llama3.1:8b")

    strategy = engine.generate_strategy(
        baseline_profile=example_baseline,
        last_failure=example_last_failure,
        test_objective="authorized defensive resilience testing in isolated lab",
        protocol_scope=["tcp", "http"],
    )

    print(json.dumps(asdict(strategy), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()