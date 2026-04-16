from protocol_mutation_gen import ProtocolMutationGenerator
from traffic_emitter import TrafficEmitter
from success_feedback_analyzer import SuccessFeedbackAnalyzer
from scapy.all import IP, TCP, Raw

if __name__ == "__main__":
    generator = ProtocolMutationGenerator(
        src_ip="192.168.10.10",
        dst_ip="192.168.20.10",
        src_port = 40000,
        dst_port=80
    )

    ttl_values = [32, 64, 128]

    # OUTPUT PRINCIPALE
    crafted_packets = generator.generate_ttl_mutations(ttl_values)

    print("\nCrafted packets generati:\n")
    for i, pkt in enumerate(crafted_packets, start=1):
        print(f"[{i}] {pkt.summary()}")  # summary() = metodo di Scapy che restituisce una rappresentazione sintetica del pacchetto. 

    # OUTPUT SECONDARIO (opzionale)
    generator.save_to_pcap(crafted_packets, "crafted_packets.pcap")
    print("\nPCAP salvato come crafted_packets.pcap")

    ################ Traffic Emitter ################ 
    # Manca il flag S per iniziare connessione
    weird_pkt = (
        IP(src="192.168.10.10", dst="192.168.20.10") /
        TCP(sport=40000, dport=80, flags="FPU") /  # flag illegali
        Raw(load=b"weird")
    )
    crafted_packets.append(weird_pkt)
    
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


