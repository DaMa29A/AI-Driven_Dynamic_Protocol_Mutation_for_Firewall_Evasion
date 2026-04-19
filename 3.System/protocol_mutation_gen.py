import re
from typing import Iterable, List
from scapy.all import IP, TCP, Packet, Raw

# es di self.new_user_ag = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
class ProtocolMutationGenerator:
    def __init__(self, ttl_value=None, user_agent=None):
        self.new_ttl = ttl_value
        self.new_user_ag = user_agent


    # Muta singolo pacchetto
    def mutate_packet(self, pkt: Packet) -> Packet:
        cloned = pkt.copy()

        if IP not in cloned:
            return cloned

        # --- cambio TTL ---
        if self.new_ttl is not None:
            cloned[IP].ttl = self.new_ttl
        
        # --- CAMBIO USER-AGENT (Livello Applicazione) ---
        if self.new_user_ag is not None:
            if TCP in cloned and Raw in cloned:
                # Controlla se il traffico è diretto/proveniente dalla porta HTTP (80)
                if cloned[TCP].dport == 80 or cloned[TCP].sport == 80:
                    try:
                        # Decodifica il payload grezzo
                        payload_str = cloned[Raw].load.decode('utf-8', errors='ignore')
                        
                        # Cerca e sostituisce l'intestazione User-Agent
                        if "User-Agent:" in payload_str:
                            new_user_agent = f"User-Agent: {self.new_user_ag}\r\n"
                            modified_payload = re.sub(
                                r"User-Agent: .*?\r\n", 
                                new_user_agent, 
                                payload_str
                            )
                            # Sovrascrive il payload del pacchetto con la nuova stringa
                            cloned[Raw].load = modified_payload.encode('utf-8')
                    except Exception:
                        pass # Ignora eventuali errori di decodifica su payload non testuali

        # --- Forza il ricalcolo checksum/lunghezze ---
        if hasattr(cloned[IP], "chksum"):
            del cloned[IP].chksum
        if hasattr(cloned[IP], "len"):
            del cloned[IP].len
        if TCP in cloned and hasattr(cloned[TCP], "chksum"):
            del cloned[TCP].chksum

        return cloned

    # Muta lista pacchetti
    def mutate_packets(self, packets: Iterable[Packet]) -> List[Packet]:
        return [self.mutate_packet(pkt) for pkt in packets]