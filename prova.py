# sudo iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 1
# sudo iptables -F OUTPUT
# sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1
# Quando hai finito : sudo iptables -D OUTPUT -p icmp -j NFQUEUE --queue-num 1

# Per avviare: sudo .venv/bin/python prova.py




# import time
# import subprocess
# from scapy.all import IP, TCP, send
# from traffic_emitter import TrafficEmitter
# from success_feedback_analyzer import SuccessFeedbackAnalyzer

# # --- CONFIGURAZIONE DEL TUO LAB ---
# TARGET_IP = "192.168.20.10"  # IP di Mint
# INTERFACE = "eth0"           # Interfaccia di Kali
# TARGET_PORT = 80             # Porta sicura (80 HTTP o 443 HTTPS)

# def run_evasion_test(test_name, trigger_function):
#     """
#     Funzione helper per avviare l'Emitter, l'Analyzer, inviare il traffico
#     e raccogliere il risultato. Ora accetta una funzione (trigger_function)
#     per generare il traffico.
#     """
#     print(f"\n{'='*10} AVVIO TEST: {test_name} {'='*10}")

#     emitter = TrafficEmitter(queue_num=1)
#     analyzer = SuccessFeedbackAnalyzer(target_ip=TARGET_IP, interface=INTERFACE, timeout=3)

#     analyzer.start_in_background()
#     emitter.start_in_background()
    
#     time.sleep(1)

#     print(f"[Main] Generazione traffico...")
#     trigger_function() # Eseguiamo la funzione che genera il pacchetto

#     reward = analyzer.wait_and_get_result()
#     emitter.stop()

#     print("-" * 45)
#     if reward == 1:
#         print(f"RISULTATO [{test_name}]: Evasione Riuscita. Reward: {reward}")
#     else:
#         print(f"RISULTATO [{test_name}]: Traffico Bloccato/Scartato. Reward: {reward}")
#     print("-" * 45 + "\n")

# # --- FUNZIONI DI GENERAZIONE TRAFFICO ---

# def trigger_icmp_ping():
#     """Genera un ping usando il sistema operativo (verrà bloccato)"""
#     subprocess.run(["ping", "-c", "1", TARGET_IP], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# def trigger_safe_scapy_tcp():
#     """
#     Genera un pacchetto TCP SYN pulito usando Scapy. 
#     Simula una legittima richiesta di connessione web.
#     """
#     # Creiamo un pacchetto IP diretto a Mint, con livello TCP (SYN flag) verso la porta 80
#     pkt = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT, flags="S")
#     # Inviamo il pacchetto silenziando l'output di default di Scapy
#     send(pkt, verbose=False)


# if __name__ == "__main__":
#     print("=== INIZIO BATTERIA DI TEST DI EVASIONE ===")

#     # TEST 1: Il Ping (Che sappiamo verrà bloccato/scartato)
#     run_evasion_test(
#         test_name="Test 1 (ICMP Ping - Bloccato)", 
#         trigger_function=trigger_icmp_ping
#     )

#     time.sleep(2)

#     # TEST 2: Pacchetto Scapy TCP (Sicuro)
#     run_evasion_test(
#         test_name="Test 2 (Scapy TCP SYN - Sicuro)", 
#         trigger_function=trigger_safe_scapy_tcp
#     )

#     print("=== BATTERIA DI TEST CONCLUSA ===")

    
import time
import subprocess
from traffic_emitter import TrafficEmitter
from success_feedback_analyzer import SuccessFeedbackAnalyzer
from protocol_mutation_gen import ProtocolMutationGenerator
from models import MutationStrategy

# --- CONFIGURAZIONE DEL TUO LAB ---
TARGET_IP = "192.168.20.10"
INTERFACE = "eth0"

# 1. Istanziamo il Mutator FUORI dall'Emitter
mutator = ProtocolMutationGenerator()

# 2. Variabile globale per tenere traccia della singola strategia corrente
current_strategy = None 

# 3. La funzione ponte tra Emitter e Mutator
def apply_active_mutation(scapy_pkt):
    """
    Questa funzione viene passata al Traffic Emitter.
    Prende il pacchetto dalla coda, usa il Mutator globale e lo restituisce mutato.
    """
    return mutator.mutate(scapy_pkt, current_strategy)


def run_evasion_test(test_name, trigger_function, strategy):
    global current_strategy
    current_strategy = strategy  # Impostiamo la singola strategia per questo specifico test

    print(f"\n{'='*10} AVVIO TEST: {test_name} {'='*10}")

    # Inizializziamo l'Emitter passandogli solo la callback, non la strategia
    emitter = TrafficEmitter(queue_num=1, mutation_callback=apply_active_mutation)
    analyzer = SuccessFeedbackAnalyzer(target_ip=TARGET_IP, interface=INTERFACE, timeout=3)

    analyzer.start_in_background()
    emitter.start_in_background()
    
    time.sleep(1) # Diamo tempo ai thread di mettersi in ascolto

    print(f"[Main] Generazione traffico...")
    trigger_function() 

    reward = analyzer.wait_and_get_result()
    emitter.stop()

    print("-" * 45)
    if reward == 1:
        print(f"RISULTATO: Evasione Riuscita (+1)")
    else:
        print(f"RISULTATO: Traffico Bloccato/Scartato (-1)")
    print("-" * 45 + "\n")


def trigger_http_get_curl():
    """Genera una vera richiesta HTTP GET per permettere la mutazione dell'User-Agent"""
    subprocess.run(["curl", "-s", "--connect-timeout", "2", f"http://{TARGET_IP}/"], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    print("=== INIZIO BATTERIA DI TEST DECOUPLED ===")

    # TEST 1: Strategia Singola - Livello 3 (TTL)[cite: 1]
    strat_1 = MutationStrategy(
        field_to_mutate="ttl",
        new_value=111,
        reasoning="Modifica del TTL per bypassare il controllo degli hop di rete."
    )
    run_evasion_test("Test 1 (Mutazione TTL a 111)", trigger_http_get_curl, strat_1)

    time.sleep(2)

    # TEST 2: Strategia Singola - Livello 4 (Window Size)[cite: 1]
    strat_2 = MutationStrategy(
        field_to_mutate="window",
        new_value=8192,
        reasoning="Modifica della TCP Window per eludere l'ispezione stateful."
    )
    run_evasion_test("Test 2 (Mutazione Window a 8192)", trigger_http_get_curl, strat_2)

    time.sleep(2)

    # TEST 3: Strategia Singola - Livello 7 (User-Agent)[cite: 1]
    strat_3 = MutationStrategy(
        field_to_mutate="user_agent",
        new_value="Windows Update Agent",
        reasoning="Offuscamento dell'User-Agent per simulare traffico Windows legittimo."
    )
    run_evasion_test("Test 3 (Mutazione User-Agent)", trigger_http_get_curl, strat_3)

    print("=== BATTERIA DI TEST CONCLUSA ===")