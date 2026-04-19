import json
from scapy.all import RandShort, IP, TCP, UDP, Raw
from llm.llm_config import DEFAULT_MODEL, BASELINE_PATH
from llm_evasion_strategy_engine import LLMEvasionStrategyEngine
from protocol_mutation_gen import ProtocolMutationGenerator
from traffic_emitter import TrafficEmitter
from success_feedback_analyzer import SuccessFeedbackAnalyzer
from rl.qtable import QTable

SRC_IP = "192.168.10.10" # ip attaccante
DST_IP = "192.168.20.10" # ip vittima

"""
Problema del port fisso [su src_port=40000]:
Se si generano 3 pacchetti mutati (es. con TTL 128, 32 e 255) e li invii tutti usando src_port=40000, 
pfSense li vedrà come appartenenti alla stessa identica sessione TCP.
Se il primo pacchetto (TTL 128) viene bloccato dal firewall, pfSense potrebbe marcare quella sessione (la porta 40000) 
come "invalida" o "chiusa". Di conseguenza, quando invii il secondo pacchetto (TTL 32) sempre dalla porta 40000, 
il firewall lo dropperà a prescindere dal TTL, semplicemente perché lo considera traffico spurio di una sessione già interrotta.
"""
SRC_PORT = RandShort()  # Genera una porta sorgente casuale ogni volta
#SRC_PORT = 40000 # Per testare con porta fissa
DST_PORT = 80 # Porta in ascolto sul server web Mint (es. 80 per HTTP, 443 per HTTPS)

def build_state_from_baseline(baseline):
    return {
        "packet_size_min": baseline.get("features", {}).get("packet_size", {}).get("stats", {}).get("min"),
        "packet_size_max": baseline.get("features", {}).get("packet_size", {}).get("stats", {}).get("max"),
        "ttl_min": baseline.get("features", {}).get("ttl", {}).get("stats", {}).get("min"),
        "ttl_max": baseline.get("features", {}).get("ttl", {}).get("stats", {}).get("max"),
        "tcp_window_min": baseline.get("features", {}).get("tcp_window_size", {}).get("stats", {}).get("min"),
        "tcp_window_max": baseline.get("features", {}).get("tcp_window_size", {}).get("stats", {}).get("max"),
    }

def print_packet_fields(pkt):
    print("\n=== Pacchetto generato ===")

    if IP in pkt:
        print(f"IP.ttl     = {pkt[IP].ttl}")
        print(f"IP.id      = {pkt[IP].id}")
        print(f"IP.flags   = {pkt[IP].flags}")
        print(f"IP.frag    = {pkt[IP].frag}")
        print(f"IP.len     = {pkt[IP].len}")
        print(f"IP.src     = {pkt[IP].src}")
        print(f"IP.dst     = {pkt[IP].dst}")

    if TCP in pkt:
        print(f"TCP.sport  = {pkt[TCP].sport}")
        print(f"TCP.dport  = {pkt[TCP].dport}")
        print(f"TCP.seq    = {pkt[TCP].seq}")
        print(f"TCP.ack    = {pkt[TCP].ack}")
        print(f"TCP.flags  = {pkt[TCP].flags}")
        print(f"TCP.window = {pkt[TCP].window}")
        print(f"TCP.options= {pkt[TCP].options}")

    if UDP in pkt:
        print(f"UDP.sport  = {pkt[UDP].sport}")
        print(f"UDP.dport  = {pkt[UDP].dport}")
        print(f"UDP.len    = {pkt[UDP].len}")

    if Raw in pkt:
        print(f"Raw.load   = {pkt[Raw].load!r}")

    print(f"summary    = {pkt.summary()}")


if __name__ == "__main__":
    generator = ProtocolMutationGenerator(
        src_ip = SRC_IP,
        dst_ip= DST_IP,
        src_port = SRC_PORT,
        dst_port = DST_PORT
    )

    print(f"[+] ProtocolMutationGenerator initialized with src_ip={generator.src_ip}, dst_ip={generator.dst_ip}, src_port={generator.src_port}, dst_port={generator.dst_port}")

    llm_engine = LLMEvasionStrategyEngine(baseline_json_path=BASELINE_PATH)

    # Ciclo di Evasione Adattivo
    evasion_success = False
    max_attempts = 10
    attempts = 0

    while not evasion_success and attempts < max_attempts:
        attempts += 1
        print(f"\n--- Ciclo di Test {attempts}/{max_attempts} ---")

        # A. Chiedi all'LLM la strategia
        llm_output_text = llm_engine.get_next_mutation()
        print(f"[*] Strategia suggerita dall'LLM:\n{llm_output_text}")

        # Parse the JSON output from the LLM
        llm_output = json.loads(llm_output_text)
        packet_count = llm_output.get("packet_count", 0)
        print(f"Numero di pacchetti da generare secondo l'LLM: {packet_count}")

        # B. Genera pacchetti mutati
        crafted_packets = []
        for pk in llm_output.get("packets", []):
            print(f"Generazione pacchetto con i seguenti campi: {pk}")
            crafted_pkt = generator.generate_from_llm_strategy(pk)
            print(f"Pacchetto generato: {print_packet_fields(crafted_pkt)}\n\n")
            crafted_packets.append(crafted_pkt)

        # C. Invia il pacchetto e raccogli il reward (+1 o -1)
        qtab = QTable()
        state = build_state_from_baseline(llm_engine.baseline)
        action = llm_output
        
        emitter = TrafficEmitter(timeout=2)
        results = emitter.send_packets(crafted_packets)

        succ_analyzer = SuccessFeedbackAnalyzer()
        feedback_results = succ_analyzer.analyze_batch(results)
        print("\nFeedback Results:")
        for pk, res, reward in feedback_results:
            print(f"Pk: {pk} - Res: {res} - Reward: {reward}")
        
        # Q-Table
        total_reward = sum(reward for _, _, reward in feedback_results)
        new_q = qtab.update(
            state_obj=state,
            action_obj=action,
            reward=total_reward,
            next_state_obj=None
        )
        
        print(f"[QTABLE] Nuovo Q-value: {new_q}")
        print(f"[QTABLE] Salvata in: {qtab.path}")