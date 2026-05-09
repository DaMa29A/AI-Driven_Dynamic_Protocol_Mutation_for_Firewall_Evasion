import threading
from scapy.all import sniff, IP, ICMP, TCP

class SuccessFeedbackAnalyzer:
    def __init__(self, target_ip, interface="eth0", timeout=3):
        """
        Inizializza il Success Feedback Analyzer.
        :param target_ip: L'IP della macchina bersaglio (Mint) per verificare le risposte legittime.
        :param interface: L'interfaccia di rete di Kali su cui fare sniffing.
        :param timeout: Tempo massimo di attesa prima di considerare il pacchetto scartato (silent drop).
        """
        self.target_ip = target_ip
        self.interface = interface
        self.timeout = timeout
        # Inizializziamo il feedback a -1 (assumiamo il fallimento per silent drop di default)
        self.feedback_score = -1 
        self._thread = None

    # Monitora: accettazioni dei pacchetti, rifiuti, risposte di errore (TCP RST, errori ICMP)
    def analyze_response(self, pkt):
        # 1. Controllo Successo: Risposta legittima dal Target (es. ICMP Echo Reply)
        if IP in pkt and pkt[IP].src == self.target_ip:
            if ICMP in pkt and pkt[ICMP].type == 0:
                print("[Analyzer] SUCCESS: Risposta ICMP legittima ricevuta dal Target!")
                self.feedback_score = 1
            elif TCP in pkt and pkt[TCP].flags == "SA":
                print("[Analyzer] SUCCESS: Risposta TCP SYN-ACK ricevuta dal Target!")
                self.feedback_score = 1

        # 2. Controllo Fallimento Attivo: Blocco del Firewall (es. pfSense/Suricata)
        # Il firewall invia un ICMP Destination Unreachable
        elif IP in pkt and ICMP in pkt and pkt[ICMP].type == 3:
            print("[Analyzer] FAILURE: Pacchetto bloccato! (ICMP Destination Unreachable)")
            self.feedback_score = -1
            
        # Il firewall chiude la connessione con un TCP Reset (RST)
        elif IP in pkt and TCP in pkt and (pkt[TCP].flags == "R" or pkt[TCP].flags == "RA"):
            print("[Analyzer] FAILURE: Pacchetto bloccato! (TCP RST)")
            self.feedback_score = -1


    # Avvia lo sniffing sulla rete. Si ferma automaticamente dopo il timeout.
    # Se non riceve nulla, il feedback_score rimarrà -1 (simulando un drop silenzioso)
    def run(self):
        print(f"[Analyzer] In ascolto su {self.interface} per {self.timeout} secondi...")
        # Filtriamo lo sniffing solo per il traffico in entrata (inbound) per non rileggere i nostri stessi invii
        sniff(iface=self.interface, filter="inbound", prn=self.analyze_response, timeout=self.timeout)
        # Nel progetto finale, qui i risultati verrebbero loggati in Redis
        print(f"[Analyzer] Sniffing concluso. Segnale generato: {self.feedback_score}")


    # Avvia l'Analyzer in un thread separato.
    def start_in_background(self):
        self.feedback_score = -1 # Resetta il punteggio per il nuovo test
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()


    # Attende la fine dello sniffing e restituisce il feedback (+1 o -1)
    def wait_and_get_result(self):
        if self._thread:
            self._thread.join()
        return self.feedback_score