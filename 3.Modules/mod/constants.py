from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"
DATA_DIR = BASE_DIR / "data"

BASELINE_JSON = INPUT_DIR / "baseline_stats.json"
LAST_FEEDBACK_JSON = INPUT_DIR / "last_feedback.json"
OUTPUT_STRATEGY_JSON = OUTPUT_DIR / "strategy.json"
HISTORY_JSON = DATA_DIR / "history.json"

OLLAMA_URL = "http://192.168.98.1:11434/api/generate"
OLLAMA_MODEL = "llama3.1:8b"
