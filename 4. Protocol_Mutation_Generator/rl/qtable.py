import json
from pathlib import Path
from typing import Any, Dict, Optional


class QTable:
    def __init__(self, path: str = "qtable.json", alpha: float = 0.1, gamma: float = 0.9):
        base_dir = Path(__file__).resolve().parent.parent
        output_dir = base_dir / "output"
        output_dir.mkdir(exist_ok=True)  # crea la cartella se non esiste
        
        if path is None:
            self.path = output_dir / "qtable.json"
        else:
            self.path = Path(path)
        
        self.alpha = alpha
        self.gamma = gamma
        self.table: Dict[str, Dict[str, float]] = self._load()

    def _load(self) -> Dict[str, Dict[str, float]]:
        if self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
        return {}

    def save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.table, f, indent=2, ensure_ascii=False)

    def make_state_key(self, state_obj: Any) -> str:
        return json.dumps(state_obj, sort_keys=True, separators=(",", ":"))

    def make_action_key(self, action_obj: Any) -> str:
        return json.dumps(action_obj, sort_keys=True, separators=(",", ":"))

    def get_q_value(self, state_key: str, action_key: str) -> float:
        return self.table.get(state_key, {}).get(action_key, 0.0)

    def set_q_value(self, state_key: str, action_key: str, value: float) -> None:
        if state_key not in self.table:
            self.table[state_key] = {}
        self.table[state_key][action_key] = value

    def update(self, state_obj: Any, action_obj: Any, reward: float, next_state_obj: Optional[Any] = None) -> float:
        state_key = self.make_state_key(state_obj)
        action_key = self.make_action_key(action_obj)

        old_q = self.get_q_value(state_key, action_key)

        if next_state_obj is not None:
            next_state_key = self.make_state_key(next_state_obj)
            next_actions = self.table.get(next_state_key, {})
            max_next_q = max(next_actions.values()) if next_actions else 0.0
        else:
            max_next_q = 0.0

        new_q = old_q + self.alpha * (reward + self.gamma * max_next_q - old_q)

        self.set_q_value(state_key, action_key, new_q)
        self.save()
        return new_q

    def best_action(self, state_obj: Any) -> Optional[Dict[str, Any]]:
        state_key = self.make_state_key(state_obj)
        actions = self.table.get(state_key, {})

        if not actions:
            return None

        best_action_key = max(actions, key=actions.get)
        return {
            "action_key": best_action_key,
            "q_value": actions[best_action_key]
        }

    def has_state(self, state_obj: Any) -> bool:
        state_key = self.make_state_key(state_obj)
        return state_key in self.table

    def pretty_print(self) -> None:
        print(json.dumps(self.table, indent=2, ensure_ascii=False))