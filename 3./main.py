from scapy.all import IP, TCP, rdpcap, wrpcap
from pathlib import Path
from protocol_mutation_gen import ProtocolMutationGenerator
from traffic_emitter import TrafficEmitter


# =========================
# CONFIGURAZIONE (COSTANTI)
# =========================
BASE_DIR = Path(__file__).resolve().parent
INPUT_PCAP= BASE_DIR / "input" / "capture.pcap"

TARGET_IP = "192.168.20.10" # ip vittima
TARGET_PORT = 80

MAX_PACKETS = 10
OUTPUT_PCAP = "mutated_packets.pcap"
SAVE_OUTPUT = True

def load_candidate_packets(pcap_file, target_ip=None, target_port=None):
    packets = rdpcap(str(pcap_file))
    candidates = []

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue

        if target_ip and pkt[IP].dst != target_ip:
            continue
        
        
        if target_port and pkt[TCP].dport != target_port:
            continue
        
        flags = pkt[TCP].flags
        if "R" in str(flags):
            continue

        candidates.append(pkt)

    return candidates

if __name__ == "__main__":
    #main()
    print(f"[+] Loading PCAP: {INPUT_PCAP}")

    candidates = load_candidate_packets(
        INPUT_PCAP,
        target_ip=TARGET_IP,
        target_port=TARGET_PORT
    )
    
    print(f"[+] Candidate packets: {len(candidates)}")
    
    # gen = ProtocolMutationGenerator()
    # all_mutations = []
    # for idx, pkt in enumerate(candidates, start=1):
    #     mutations = gen.generate(pkt)
    #     all_mutations.extend(mutations)

    #     src_ip = pkt[IP].src
    #     dst_ip = pkt[IP].dst
    #     src_port = pkt[TCP].sport
    #     dst_port = pkt[TCP].dport

    #     print(
    #         f"[+] Packet {idx}: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
    #         f"{len(mutations)} mutations"
    #     )

    # print(f"\n[+] Total mutations: {len(all_mutations)}")
    
    emitter = TrafficEmitter()
    results = emitter.emit_mutations(candidates)

    for r in results:
        print(r)
    
    