from scapy.all import IP, TCP
from mitmproxy import http
from mod.protocol_mutation_generator import ProtocolMutationGenerator

generator = ProtocolMutationGenerator()

# Packet test
base_pkt = IP(dst="192.168.20.10", ttl=64) / TCP(
    dport=80,
    flags="S",
    window=64240
)

strategy = {
    "ttl": 62,
    "tcp_window": 508,
    "user_agent": None
}

mutated_pkt = generator.apply_packet_strategy(base_pkt, strategy)

print("Original TTL:", base_pkt[IP].ttl)
print("Mutated TTL:", mutated_pkt[IP].ttl)

print("Original Window:", base_pkt[TCP].window)
print("Mutated Window:", mutated_pkt[TCP].window)


# HTTP test
class FakeFlow:
    def __init__(self, request):
        self.request = request
        
# 1. Creazione richiesta HTTP fake
req = http.Request.make(
    "GET",
    "http://192.168.20.10/mfolder/index.html",
    headers={
        "User-Agent": "curl/7.68.0",
        "Accept": "*/*"
    }
)

flow = FakeFlow(req)

# 2. Stampa headers originali
print("\n[Original HTTP Headers]")
for k, v in flow.request.headers.items():
    print(f"{k}: {v}")

# 3. Strategia (simula output del planner)
strategy = {
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# 4. Applica mutazione
mutated_flow, mutation_log = generator.apply_http_strategy(flow, strategy)

# 5. Stampa headers mutati
print("\n[Mutated HTTP Headers]")
for k, v in mutated_flow.request.headers.items():
    print(f"{k}: {v}")

# 6. Log mutazione
print("\n[Mutation Log]")
print(mutation_log)
