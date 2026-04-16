import json

def load_json(json_path):
    """Carica un file JSON e restituisce il contenuto come dizionario."""
    with open(json_path, "r") as f:
        data = json.load(f)
    return data

def json_to_string(data: dict, pretty: bool = True) -> str:
    """Converte un oggetto Python (dict) in stringa JSON."""
    try:
        if pretty:
            return json.dumps(data, indent=2, ensure_ascii=False)
        else:
            return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Errore nella serializzazione JSON: {e}")