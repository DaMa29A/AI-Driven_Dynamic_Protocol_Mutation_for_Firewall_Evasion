from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
BASELINE_PATH = BASE_DIR / "input" / "baseline_stats.json"


DEFAULT_MODEL = "llama3.1:8b"
#DEFAULT_MODEL = "llama3.2:3b"