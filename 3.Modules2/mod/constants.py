from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_DIR = BASE_DIR / "input"
BASELINE_JSON = INPUT_DIR / "baseline_stats.json"

OLLAMA_URL = "http://192.168.98.1:11434/api/generate"
OLLAMA_BASE_URL = "http://192.168.98.1:11434"
OLLAMA_MODEL = "llama3.1:8b"
#OLLAMA_MODEL = "llama3.2:3b"

TARGET_IP = "192.168.20.10"
BASE_URL = f"http://{TARGET_IP}"