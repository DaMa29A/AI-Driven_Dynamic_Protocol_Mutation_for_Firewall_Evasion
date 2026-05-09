from mod.history_manager import HistoryManager

def add_to_history(strategy, feedback):
    record = history.create_record(
        strategy,
        feedback
    )
    history.append(record)


history = HistoryManager()

strategy = {
    "strategy_id": "s1",
    "http": {
        "method": "GET",
        "path": "/mfolder/index.html",
        "headers": {"User-Agent": "curl/8.0"}
    },
    "packet": {
        "ttl": 64,
        "tcp_window": 64240
    }
}

fb = {
    "verdict": "PASS",
    "reward": 1.0,
    "reason": "HTTP status 200"
}

add_to_history(strategy, fb)

