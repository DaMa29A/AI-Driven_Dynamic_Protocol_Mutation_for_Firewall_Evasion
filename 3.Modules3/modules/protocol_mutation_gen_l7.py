import os
import json
import sys
from mitmproxy import http
# --- FIX PER I PERCORSI ---
# Calcoliamo il percorso assoluto della cartella in cui si trova questo script (modules)
current_dir = os.path.dirname(os.path.abspath(__file__))
# Saliamo di un livello per arrivare alla cartella root (3.Modules3)
root_dir = os.path.dirname(current_dir)
# Aggiungiamo la root ai percorsi in cui Python cerca i moduli
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
# --------------------------
# ORA possiamo importare la cartella utils senza problemi!
from utils.models import MutationStrategy
from utils.utils import load_json

class ProtocolMutatorL7:
    def __init__(self, strategy_path: str):
        self.strategy_path = strategy_path

    def request(self, flow: http.HTTPFlow):
        data = load_json(self.strategy_path)
    
        if not data:
            return

        try:
            strategy = MutationStrategy(**data)
        except Exception as e:
            print(f"[Mitmproxy L7] Errore di validazione Pydantic: {e}")
            return

        field = strategy.field_to_mutate
        new_value = str(strategy.new_value)
        old_value = flow.request.headers.get(field, "[Non esisteva]")

        print(f"\n[Mitmproxy L7] Request intercepted to: {flow.request.pretty_host}")
        print(f"[Mitmproxy L7] Field: {field}")
        print(f"[Mitmproxy L7] Old value: {old_value}")
        print(f"[Mitmproxy L7] New value: {new_value}")
        print(f"[Mitmproxy L7] Reasoning: {strategy.reasoning}")

        flow.request.headers[field] = new_value

addons = [
    ProtocolMutatorL7("mutation_strategy.json")
]