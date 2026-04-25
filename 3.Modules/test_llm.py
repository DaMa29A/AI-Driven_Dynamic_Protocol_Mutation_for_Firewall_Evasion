from mod.constants import (
    BASELINE_JSON,
    LAST_FEEDBACK_JSON,
    OUTPUT_STRATEGY_JSON,
    OLLAMA_URL,
    OLLAMA_MODEL,
)
from mod.llm_strategy_engine import LLMEvasionStrategyEngine
from mod.utils import load_json, save_json


def main():
    baseline = load_json(BASELINE_JSON)

    if baseline is None:
        raise FileNotFoundError(f"Baseline non trovato: {BASELINE_JSON}")

    last_feedback = load_json(LAST_FEEDBACK_JSON, default=None)

    engine = LLMEvasionStrategyEngine(
        ollama_url=OLLAMA_URL,
        model=OLLAMA_MODEL
    )

    strategy = engine.generate_strategy(
        baseline=baseline,
        last_feedback=last_feedback
    )

    save_json(OUTPUT_STRATEGY_JSON, strategy)

    print("[+] Strategia generata:")


if __name__ == "__main__":
    main()