import json
from datetime import datetime, timezone
from pathlib import Path
from .constants import HISTORY_JSON
from .utils import load_json


class HistoryManager:
    def __init__(self):
        self.path = Path(HISTORY_JSON)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # Carica json
    def _load(self):
        try:
            data = load_json(self.path, default=[])
            return data if data else []
        except Exception:
            return []

    # Calcola numero prossima iterazione
    def _get_next_iteration(self):
        data = self._load()

        if not data:
            return 1

        last = data[-1]
        return last.get("iteration", 0) + 1

    # Aggiungi al file nuova strategia
    def append(self, record: dict):
        data = self._load()
        data.append(record)

        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    # Crea nuovo record con startegia + risultato
    def create_record(self, strategy, feedback):
        iteration = self._get_next_iteration()

        return {
            "iteration": iteration,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "strategy": strategy,
            "feedback": feedback
        }