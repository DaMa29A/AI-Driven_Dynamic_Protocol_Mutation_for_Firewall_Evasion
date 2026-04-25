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
    HISTORY_JSON
)

"""
sudo ./.venv/bin/python ./3.Modules/main.py
"""
target_ip = "192.168.20.10"
base_url = f"http://{target_ip}"
    
    
def get_strategy_params(strategy):
    http_str = strategy.get("http")
    url = base_url + http_str.get("path")
    method = http_str.get("method")
    ua = http_str.get("headers").get("User-Agent")
    # headers_normal = {
    # "User-Agent": ua,
    # "Accept-Language": ""
    # }
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
    

def main(): 
    generator = ProtocolMutationGenerator()
    emitter = TrafficEmitter()
    feedback = SuccessFeedbackAnalyzer()
    history = HistoryManager(HISTORY_JSON)
    
    i = 0
    while i < 3:
        ############################# START LLM #############################
        baseline = load_json(BASELINE_JSON)

        if baseline is None:
            raise FileNotFoundError(f"Baseline non trovato: {BASELINE_JSON}")

        last_feedback = load_json(LAST_FEEDBACK_JSON, default=None)

        engine = LLMEvasionStrategyEngine(
            ollama_url=OLLAMA_URL,
            model=OLLAMA_MODEL
        )
        
        strategy = engine.generate_strategy(
            baseline=baseline,
            last_feedback=last_feedback
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
        record = history.create_record(
            iteration=i + 1,
            strategy=strategy,
            feedback=fb
        )

        history.append(record)
            
        # Altrimenti intercetto e modifico
    
        i += 1;
    



if __name__ == "__main__":
    main()