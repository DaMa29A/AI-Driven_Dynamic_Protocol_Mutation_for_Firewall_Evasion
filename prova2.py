# sudo iptables -F OUTPUT
# sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1

# mitmdump -s protocol_mutation_gen.py -p 8080

import time
import subprocess
from traffic_emitter import TrafficEmitter
from success_feedback_analyzer import SuccessFeedbackAnalyzer
from protocol_mutation_gen import ProtocolMutationGenerator  # Importa dal file che hai appena unito
from models import MutationStrategy

TARGET_IP = "192.168.20.10"
INTERFACE = "eth0"

mutator = ProtocolMutationGenerator()
current_strategy = None 

def apply_active_mutation(scapy_pkt):
    return mutator.mutate(scapy_pkt, current_strategy)

def run_evasion_test(test_name, trigger_function, strategy):
    global current_strategy
    current_strategy = strategy  

    print(f"\n{'='*10} AVVIO TEST: {test_name} {'='*10}")

    emitter = TrafficEmitter(queue_num=1, mutation_callback=apply_active_mutation)
    analyzer = SuccessFeedbackAnalyzer(target_ip=TARGET_IP, interface=INTERFACE, timeout=3)

    analyzer.start_in_background()
    emitter.start_in_background()
    
    time.sleep(1) 

    print(f"[Main] Generazione traffico (Dogana 1: Mitmproxy -> Dogana 2: NFQUEUE)...")
    trigger_function() 

    reward = analyzer.wait_and_get_result()
    emitter.stop()

    print("-" * 45)
    if reward == 1:
        print(f"RISULTATO: Evasione Riuscita (+1)")
    else:
        print(f"RISULTATO: Traffico Bloccato/Scartato (-1)")
    print("-" * 45 + "\n")


def trigger_http_with_proxy():
    """
    Genera la richiesta HTTP e la forza a passare attraverso Mitmproxy (porta 8080).
    Mitmproxy applicherà la mutazione L7 e poi inoltrerà il pacchetto a NFQUEUE.
    """
    subprocess.run([
        "curl", 
        "-s", 
        "--proxy", "http://127.0.0.1:8080", # <-- Il passaggio fondamentale per l'L7
        "--connect-timeout", "2", 
        "-m", "3", 
        f"http://{TARGET_IP}/"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    print("=== INIZIO BATTERIA DI TEST IBRIDA (Mitmproxy + Scapy) ===")

    # Testiamo un attacco ibrido: Mitmproxy cambia l'User-Agent, Scapy cambia il TTL!
    strat_1 = MutationStrategy(
        field_to_mutate="ttl",
        new_value=111,
        reasoning="Scapy intercetta il pacchetto uscito da Mitmproxy e gli altera il TTL a 111."
    )
    
    run_evasion_test(
        test_name="Test Ibrido (L7 User-Agent + L3 TTL)", 
        trigger_function=trigger_http_with_proxy, 
        strategy=strat_1
    )

    print("=== BATTERIA DI TEST CONCLUSA ===")