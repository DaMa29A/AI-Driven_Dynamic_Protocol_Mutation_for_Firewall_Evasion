from scapy.packet import Packet
from scapy.layers.inet import IP, TCP
from utils.models import MutationStrategy

class ProtocolMutator:
    def __init__(self):
        pass
    
    def mutate(self, pkt: Packet, strategy: MutationStrategy) -> Packet:
        # Se non è IP o non c'è una strategia, restituiamo il pacchetto originale
        if not strategy or not pkt.haslayer(IP):
            return pkt 

        scapy_pkt = pkt.copy()
        field = strategy.field_to_mutate.lower()

        # Sicurezza: assicuriamoci che il valore fornito dall'AI sia convertibile in intero
        try:
            val = int(strategy.new_value)
        except (ValueError, TypeError):
            print(f"[Mutation Gen] ⚠️ Errore: il valore '{strategy.new_value}' non è un intero valido per {field}.")
            return scapy_pkt

        # 1. MUTAZIONE L3: Modifica del campo TTL
        if field == "ttl":
            print(f"[Mutation Gen] Alterazione TTL da {scapy_pkt[IP].ttl} a {val}")
            scapy_pkt[IP].ttl = val

        # 2. MUTAZIONE L4: Modifica del campo TCP Window Size
        elif field == "window" and scapy_pkt.haslayer(TCP):
            print(f"[Mutation Gen] Alterazione TCP Window da {scapy_pkt[TCP].window} a {val}")
            scapy_pkt[TCP].window = val
            
        else:
            # Se la mutazione non è supportata o manca il livello TCP, ritorniamo il pacchetto
            return scapy_pkt

        # Sfruttiamo il metodo dedicato per il ricalcolo
        return self._recalc_checksums(scapy_pkt)

    def clone_and_recalc(self, pkt: Packet) -> Packet:
        """
        Crea una copia del pacchetto e forza il ricalcolo dei checksum.
        """
        return self._recalc_checksums(pkt.copy())

    def _recalc_checksums(self, pkt: Packet) -> Packet:
        """
        Metodo interno: elimina le lunghezze e i checksum per forzare Scapy a ricalcolarli
        prima di inviare il pacchetto in rete.
        """
        if pkt.haslayer(IP):
            del pkt[IP].len
            del pkt[IP].chksum
            
        if pkt.haslayer(TCP):
            del pkt[TCP].chksum
            
        return pkt