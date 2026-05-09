import json
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

emitter = TrafficEmitter()
feedback_analyzer = SuccessFeedbackAnalyzer()
engine = LLMEvasionStrategyEngine(
        ollama_url=OLLAMA_BASE_URL,
        model=OLLAMA_MODEL
)

N = 10
i = 0

last_feedback_for_llm = None 
strategies = []
drops = []

while i < N:
    print(f"\n--- TEST [{i+1}] ---") 
    
    strategy_dict = engine.generate_tcp_strategy(
        baseline=load_json(BASELINE_JSON),
        last_feedback=last_feedback_for_llm
    )
    
    print(f"Strategia generata: {strategy_dict}")
    
    strategies.append(strategy_dict)
    
    # # --- QUI IN MEZZO CI VA IL TUO CODICE SCAPY ---
    # # Costruisci il pacchetto, lo invii (res = emitter.send_packet(...))
    # # e ottieni il feedback della rete (fb = feedback_analyzer.analyze_result(res))
    
    # # Per finta, simuliamo che la rete risponda sempre con un DROP
    # fb = {"verdict": "BLOCK", "reward": -1.0, "reason": "Timeout"} 
    # print(f"Risultato di Rete: {fb}")
    
    # # 2. Aggiorniamo la variabile per il PROSSIMO giro
    # if fb.get("reward") == -1.0:
    #     # Se ha fallito, popoliamo la variabile con i dettagli
    #     last_feedback_for_llm = {
    #         "verdict": fb.get("verdict"),
    #         "reward": fb.get("reward"),
    #         "reason": fb.get("reason"),
    #         "failed_mutation": strategy_dict # Importante: passiamo cosa ha fallito
    #     }
    # else:
    #     print("Successo! Evasione completata.")
    #     break
        
    i += 1