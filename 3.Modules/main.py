from mod.protocol_mutation_generator import ProtocolMutationGenerator
from mod.traffic_emitter import TrafficEmitter
from mod.success_feedback_analyzer import SuccessFeedbackAnalyzer
from mod.llm_strategy_engine import LLMEvasionStrategyEngine
from mod.history_manager import HistoryManager
from mod.utils import load_json, save_json
from mod.constants import (
    BASELINE_JSON,
    LAST_FEEDBACK_JSON,
    OUTPUT_STRATEGY_JSON,
    OLLAMA_URL,
    OLLAMA_MODEL,
    BASE_URL
)

"""
sudo ./.venv/bin/python ./3.Modules/main.py
"""
history = HistoryManager()
    
# def get_strategy_params(strategy):
#     http_str = strategy.get("http")
#     url = BASE_URL + http_str.get("path")
#     method = http_str.get("method")
#     ua = http_str.get("headers").get("User-Agent")
#     # headers_normal = {
#     # "User-Agent": ua,
#     # "Accept-Language": ""
#     # }
#     headers = {
#     "User-Agent": ua
#     }
    
#     return url, method, headers

def get_strategy_params(strategy):
    http_str = strategy.get("http", {})

    path = http_str.get("path", "")
    method = http_str.get("method", "")
    headers_str = http_str.get("headers", {})

    ua = headers_str.get("User-Agent", "")

    url = BASE_URL + path if path else ""

    headers = {
        "User-Agent": ua
    }

    return url, method, headers


def make_last_feedback(feedback, last_strategy):
    http_str = last_strategy.get("http")
    packet_str = last_strategy.get("packet")
    result = f"Esito: {feedback.get("verdict")} - {feedback.get("reason")}"
    return {
        "http": http_str,
        "packet": packet_str,
        "result": result
    }


def add_to_history(strategy, feedback):
    record = history.create_record(
        strategy,
        feedback
    )
    history.append(record)
    

def main(): 
    generator = ProtocolMutationGenerator()
    emitter = TrafficEmitter()
    feedback = SuccessFeedbackAnalyzer()
    
    i = 0
    while i < 19:
        ############################# START LLM #############################
        baseline = load_json(BASELINE_JSON)

        if baseline is None:
            raise FileNotFoundError(f"Baseline non trovato: {BASELINE_JSON}")

        last_feedback = load_json(LAST_FEEDBACK_JSON, default=None)

        engine = LLMEvasionStrategyEngine(
            ollama_url=OLLAMA_URL,
            model=OLLAMA_MODEL
        )
        
        if not last_feedback:
            ls = ""
        else:
            ls = last_feedback.get("http").get("headers").get("User-Agent")
        
        strategy = engine.generate_strategy(
            baseline=baseline,
            last_feedback=ls
        )

        save_json(OUTPUT_STRATEGY_JSON, strategy)
        
        
        ############################# PROTOCOL MUTATION GENERATOR #############################
        last_strategy = load_json(OUTPUT_STRATEGY_JSON)
        generator.add_strategy(last_strategy)
        
        # Primo ciclo, invio prima richiesta
        #if i == 0:
        url, method, headers = get_strategy_params(last_strategy)
        
        method = "GET" #Problema che a volte manda post
        
        print(f"url:{url}\nmethod:{method}\nheaders:{headers}")
        
        res = emitter.send_http_request(
            url = url,
            method = method,
            headers = headers
        )
        
        fb = feedback.analyze_result(res)
        print(fb)
        
        last_feedback = make_last_feedback(fb, last_strategy)
        save_json(LAST_FEEDBACK_JSON, last_feedback)
        
        # 7. Salva history completa
        add_to_history(strategy, fb)
            
        # Altrimenti intercetto e modifico
        i += 1;
    



if __name__ == "__main__":
    main()