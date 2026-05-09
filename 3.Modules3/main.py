# sudo iptables -F OUTPUT
# sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1
# sudo iptables -A OUTPUT -p tcp --dport 80 -d 192.168.20.10 -j NFQUEUE --queue-num 1

# mitmdump -s ./3\.Modules3/modules/protocol_mutation_gen_l7.py -p 8080

# sudo .venv/bin/python ./3\.Modules3/main.py 

import time
import os
import subprocess
from utils.models import MutationStrategy
from utils.utils import save_json 
from modules.protocol_mutation_gen import ProtocolMutator
from modules.traffic_emitter import TrafficEmitter
from modules.success_feedback_analyzer import SuccessFeedbackAnalyzer

# --- CONFIGURAZIONI ---
TARGET_IP = "192.168.20.10"
INTERFACE = "eth0"
MITM_PROXY_URL = "http://127.0.0.1:8080"
STRATEGY_FILE = "mutation_strategy.json"

# Inizializziamo il mutatore L3/L4 (Scapy)
l3_mutator = ProtocolMutator()
current_l3_strategy = None  # Variabile globale che Scapy leggerà ad ogni pacchetto

def apply_scapy_mutation(scapy_pkt):
    """Callback passata al Traffic Emitter per le mutazioni L3/L4"""
    return l3_mutator.mutate(scapy_pkt, current_l3_strategy)

def trigger_traffic():
    """Genera la richiesta curl facendola passare obbligatoriamente per Mitmproxy"""
    subprocess.run([
        "curl", 
        "-s", 
        "--proxy", MITM_PROXY_URL, 
        "--connect-timeout", "2", 
        "-m", "3", 
        f"http://{TARGET_IP}/"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_evasion_test(test_name: str, strategy: MutationStrategy):
    global current_l3_strategy
    
    print(f"\n{'='*15} AVVIO: {test_name} {'='*15}")

    # --- 1. SMISTAMENTO DELLA STRATEGIA (IL CERVELLO DEL MAIN) ---
    field = strategy.field_to_mutate.lower()
    
    if field in ["user_agent", "user-agent", "accept_language"]:
        # È una mutazione L7! Scriviamo il file JSON per Mitmproxy
        print(f"[Main] Smistamento L7: Scrittura di {STRATEGY_FILE} per Mitmproxy")
        
        # Pydantic usa .dict() o .model_dump() per trasformare l'oggetto in dizionario
        strategy_dict = strategy.dict() if hasattr(strategy, 'dict') else strategy.model_dump()
        save_json(STRATEGY_FILE, strategy_dict)
        
        # Scapy non deve fare nulla per questo test
        current_l3_strategy = None 
    else:
        # È una mutazione L3/L4 (es. ttl, window)! La diamo a Scapy
        print(f"[Main] Smistamento L3/L4: Caricamento in RAM per Scapy")
        current_l3_strategy = strategy
        
        # Eliminiamo il vecchio file JSON per assicurarci che Mitmproxy 
        # non applichi per sbaglio una vecchia mutazione L7
        if os.path.exists(STRATEGY_FILE):
            os.remove(STRATEGY_FILE)

    # --- 2. AVVIO MOTORI DI RETE ---
    emitter = TrafficEmitter(queue_num=1, mutation_callback=apply_scapy_mutation)
    analyzer = SuccessFeedbackAnalyzer(target_ip=TARGET_IP, interface=INTERFACE, timeout=3)

    analyzer.start_in_background()
    emitter.start_in_background()
    
    # Diamo un secondo ai thread per mettersi in ascolto
    time.sleep(1) 

    # --- 3. LANCIO ATTACCO E RACCOLTA FEEDBACK ---
    print(f"[Main] 🚀 Esecuzione richiesta curl...")
    trigger_traffic() 

    # Aspettiamo il verdetto dallo sniffer
    reward = analyzer.wait_and_get_result()
    emitter.stop()

    # --- 4. RISULTATO ---
    print("-" * 50)
    if reward == 1:
        print(f"RISULTATO FINALE: Evasione Riuscita (+1)")
    else:
        print(f"RISULTATO FINALE: Traffico Bloccato o Droppato (-1)")
    print("-" * 50 + "\n")


if __name__ == "__main__":
    print("=== INIZIO BATTERIA DI TEST IBRIDA (L7 + L3) ===")

    # 1. Creiamo il primo oggetto (Livello 7)
    strat_1 = MutationStrategy(
        field_to_mutate="User-Agent",
        new_value="Windows Update Agent/10.0",
        reasoning="Bypass regole HTTP standard fingendo traffico di sistema Windows."
    )
    
    # 2. Creiamo il secondo oggetto (Livello 3)
    strat_2 = MutationStrategy(
        field_to_mutate="ttl",
        new_value=111,
        reasoning="Elusione ispezione hop-based alterando il Time To Live."
    )

    # Eseguiamo in sequenza
    run_evasion_test("Test 1 - Mutazione Applicativa (Mitmproxy)", strat_1)
    
    time.sleep(2) # Pausa tra i test
    
    run_evasion_test("Test 2 - Mutazione di Rete (Scapy)", strat_2)
    
    # Pulizia finale
    if os.path.exists(STRATEGY_FILE):
        os.remove(STRATEGY_FILE)
        
    print("=== BATTERIA CONCLUSA ===")