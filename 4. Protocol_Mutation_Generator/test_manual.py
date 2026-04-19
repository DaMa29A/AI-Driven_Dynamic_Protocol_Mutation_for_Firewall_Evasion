from protocol_mutation_gen import ProtocolMutationGenerator
from traffic_emitter import TrafficEmitter
from success_feedback_analyzer import SuccessFeedbackAnalyzer
from scapy.all import IP, TCP, Raw
# from rl.qtable import QTable

if __name__ == "__main__":
    generator = ProtocolMutationGenerator(
        src_ip="192.168.10.10",
        dst_ip="192.168.20.10",
        src_port=40000,
        dst_port=80
    )

    # 1. Generiamo i pacchetti di test per il TTL (flag SYN di default)
    ttl_values = [32, 64, 128]
    crafted_packets = generator.generate_ttl_mutations(ttl_values)

    print("\nCrafted packets generati:\n")
    for i, pkt in enumerate(crafted_packets, start=1):
        print(f"[{i}] {pkt.summary()}") 

    generator.save_to_pcap(crafted_packets, "crafted_packets.pcap")
    print("\nPCAP salvato come crafted_packets.pcap")

    ################ Il Payload Malevolo ################ 
    # Sostituiamo il weird_pkt con un vero attacco HTTP a livello 7
    malicious_payload = b"GET / HTTP/1.1\r\nHost: 192.168.20.10\r\nUser-Agent: sqlmap\r\n\r\n"
    
    # Nota: Usiamo il flag PA (Push + Acknowledgment) perché stiamo spingendo dati (payload)
    sqlmap_pkt = (
        IP(src="192.168.10.10", dst="192.168.20.10") /
        TCP(sport=40000, dport=80, flags="PA") / 
        Raw(load=malicious_payload)
    )
    
    # Aggiungiamo il pacchetto infetto alla lista da inviare
    crafted_packets.append(sqlmap_pkt)
    
    ################ Traffic Emitter ################
    emitter = TrafficEmitter(timeout=2)
    results = emitter.send_packets(crafted_packets)

    print("\nFinal Results:")
    for pk, res in results:
        print(f"Pk: {pk} - Res: {res}")

    ################ Success Feedback Analyzer ################
    succ_analyzer = SuccessFeedbackAnalyzer()
    feedback_results = succ_analyzer.analyze_batch(results)

    print("\nFeedback Results:")
    for pk, res, reward in feedback_results:
        print(f"Pk: {pk} - Res: {res} - Reward: {reward}")