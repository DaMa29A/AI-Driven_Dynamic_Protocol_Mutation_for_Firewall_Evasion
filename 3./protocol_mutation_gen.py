from scapy.all import IP, TCP, rdpcap, wrpcap
from pathlib import Path

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


class ProtocolMutationGenerator:
    def __init__(self):
        #self.ttl_values = [32, 128, 255]
        #self.window_values = [512, 1024, 4096, 8192, 64240]
        self.ttl_values = [32]

    def clone_and_recalc(self, pkt):
        p = pkt.copy()

        if IP in p:
            if hasattr(p[IP], "len"):
                del p[IP].len
            if hasattr(p[IP], "chksum"):
                del p[IP].chksum

        if TCP in p and hasattr(p[TCP], "chksum"):
            del p[TCP].chksum

        return p

    def mutate_ttl(self, pkt):
        mutations = []
        if IP not in pkt:
            return mutations

        original = pkt[IP].ttl
        for ttl in self.ttl_values:
            if ttl == original:
                continue

            p = pkt.copy()
            p[IP].ttl = ttl
            p = self.clone_and_recalc(p)

            mutations.append({
                "mutation_type": "ttl",
                "original_value": original,
                "mutated_value": ttl,
                "packet": p
            })

        return mutations

    def mutate_window(self, pkt):
        mutations = []
        if TCP not in pkt:
            return mutations

        original = pkt[TCP].window
        for win in self.window_values:
            if win == original:
                continue

            p = pkt.copy()
            p[TCP].window = win
            p = self.clone_and_recalc(p)

            mutations.append({
                "mutation_type": "tcp_window",
                "original_value": original,
                "mutated_value": win,
                "packet": p
            })

        return mutations

    # Prende un singolo pacchetto e restituisce tutte le sue varianti mutate.
    def generate(self, pkt):
        mutations = []
        mutations.extend(self.mutate_ttl(pkt))
        #mutations.extend(self.mutate_window(pkt))
        return mutations


def save_mutations_to_pcap(mutations, output_pcap):
    packets = [m["packet"] for m in mutations]
    if packets:
        wrpcap(output_pcap, packets)    