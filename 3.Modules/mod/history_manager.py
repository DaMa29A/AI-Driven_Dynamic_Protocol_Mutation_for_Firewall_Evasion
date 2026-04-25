import json
from pathlib import Path
from datetime import datetime


class HistoryManager:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self):
        if not self.path.exists():
            return []

        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def append(self, record: dict):
        data = self.load()
        data.append(record)

        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def create_record(self, iteration, strategy, feedback):
        return {
            "iteration": iteration,
            "timestamp": datetime.utcnow().isoformat(),
            "strategy": strategy,
            "feedback": feedback
        }