# traffic_emitter.py
from netfilterqueue import NetfilterQueue
from scapy.all import IP
import threading

class TrafficEmitter:
    # Ora accetta solo la coda e una funzione esterna (opzionale) per manipolare il payload
    def __init__(self, queue_num=1, mutation_callback=None):
        self.queue_num = queue_num
        self.nfqueue = NetfilterQueue()
        self.is_running = False
        self._thread = None
        self.mutation_callback = mutation_callback  # <--- Il ponte con l'esterno

    def process_packet(self, nf_pkt):
        # 1. Estraiamo il pacchetto
        scapy_pkt = IP(nf_pkt.get_payload())
        
        # 2. Se ci hanno passato una funzione di mutazione da fuori, glielo diamo
        if self.mutation_callback:
            scapy_pkt = self.mutation_callback(scapy_pkt)
            
        # 3. Aggiorniamo la coda con i byte (mutati o meno) e spediamo
        nf_pkt.set_payload(bytes(scapy_pkt))
        nf_pkt.accept()

    
    # Avvia l'ascolto della coda in modo bloccante.
    def run(self):
        print(f"[Traffic Emitter] Avvio in ascolto sulla coda {self.queue_num}...")
        self.nfqueue.bind(self.queue_num, self.process_packet)
        try:
            self.nfqueue.run()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    
    # Avvia il Traffic Emitter in un thread separato per non bloccare il programma principale.
    def start_in_background(self):
        if not self.is_running:
            self.is_running = True
            self._thread = threading.Thread(target=self.run, daemon=True)
            self._thread.start()


    # Ferma l'intercettazione e libera la coda.
    def stop(self):
        if self.is_running:
            print("[Traffic Emitter] Arresto del modulo...")
            self.nfqueue.unbind()
            self.is_running = False