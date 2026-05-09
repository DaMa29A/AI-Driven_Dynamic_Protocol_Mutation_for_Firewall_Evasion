from mod.llm_strategy_engine import LLMEvasionStrategyEngine
from mod.traffic_emitter import TrafficEmitter
from mod.success_feedback_analyzer import SuccessFeedbackAnalyzer
from mod.utils import load_json
from mod.constants import (
    OLLAMA_MODEL,
    OLLAMA_BASE_URL, 
    BASE_URL,
    BASELINE_JSON
)

def make_headers(user_agent):
    headers = {
        "User-Agent": user_agent
    }
    return headers

def make_url(path):
    url = BASE_URL + path
    return url

def start_cycle(n_cycles):
    strategies = []
    drops = []
    i = 0;
    while i < n_cycles:
        print(f"TEST [{i+1}] ...") 
        strategy = engine.generate_strategy(
            baseline=None,
            last_feedback=None
        )
        strategies.append(strategy)
        print(f"Stretegy: {strategy}")
        headers = make_headers(strategy)
        url = make_url("/index.html")
        res = emitter.send_http_request(
            url = url,
            method = "GET",
            headers = headers
        )
        fb = feedback_analyzer.analyze_result(res)
        if fb.get("reward") == -1.0:
            drops.append(strategy)
        print(f"Feedback:\n{fb}")
        i+=1
    return strategies, drops
        
def check_single_strategy(user_agent):
    strategy = user_agent
    headers = make_headers(strategy)
    url = make_url("/index.html")
    res = emitter.send_http_request(
        url = url,
        method = "GET",
        headers = headers
    )
    fb = feedback_analyzer.analyze_result(res)
    print(f"Feedback:\n{fb}")
    

N = 1

emitter = TrafficEmitter()
feedback_analyzer = SuccessFeedbackAnalyzer()
engine = LLMEvasionStrategyEngine(
        ollama_url=OLLAMA_BASE_URL,
        model=OLLAMA_MODEL
)

# strategies , drops = start_cycle(50)
# print(f"Drops: {len(drops)}")
# print(drops)

check_single_strategy("sqlmap")
# check_single_startegy("sQlMaP")
#check_single_strategy("sqlmap")

# strategies_unique = list(set(strategies))
# print(f"Stretegies different: {len(strategies_unique)}")
# print(f"{strategies_unique}")
# print(f"Drops: {len(drops)}")
# print(f"{drops}")
