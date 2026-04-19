# sudo apt update
# sudo apt install -y build-essential python3-dev libnfnetlink-dev libnetfilter-queue-dev
# pip install NetfilterQueue

# Offloading
# ethtool -K eth0 tx off rx off tso off gso off gro off
# iptables -I OUTPUT -p tcp -d 192.168.3.10 -j NFQUEUE --queue-num 1

'''
Funzioni:
ricevere pacchetti già creati dal sistema operativo;
convertirli in pacchetti Scapy;
passarli al ProtocolMutationGenerator;
sostituire il payload originale con quello mutato;
rimandare il pacchetto nello stack di rete.
'''

from netfilterqueue import NetfilterQueue
from scapy.all import IP
import subprocess
from scapy.all import IP, TCP, Packet
from protocol_mutation_gen import ProtocolMutationGenerator
from success_feedback_analyzer import SuccessFeedbackAnalyzer


class TrafficEmitter:
    def __init__(self, queue_num=1):
        self.queue_num = queue_num #il numero della coda NFQUEUE a cui ti agganci;
        self.mutator = ProtocolMutationGenerator(ttl_value=64, user_agent="sqlmap")
        self.nfqueue = NetfilterQueue()
        self.feedback_analyzer = SuccessFeedbackAnalyzer()
        print("Emitter")

    def _process_packet(self, packet):
        """
        Callback NFQUEUE -> modifica pacchetto -> reinserisce
        """
        scapy_pkt = IP(packet.get_payload())

        if scapy_pkt.haslayer(IP):

            # registra il flow solo per il primo SYN TCP
            if TCP in scapy_pkt and scapy_pkt[TCP].flags == 0x02:
                flow_info = self.extract_flow_info(scapy_pkt)

                if flow_info is not None:
                    self.feedback_analyzer.register_outgoing_flow(flow_info)
                    print(f"[FLOW REGISTERED] {flow_info}")

            mutated_pkt = self.mutator.mutate_packet(scapy_pkt)
            packet.set_payload(bytes(mutated_pkt))

            flags = scapy_pkt[TCP].sprintf("%TCP.flags%")
            print(f"[MOD] TTL={mutated_pkt[IP].ttl} flags={flags}")

        packet.accept()
        
        
    def extract_flow_info(self, pkt: Packet) -> dict | None:
        if IP not in pkt:
            return None

        flow = {
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "protocol": "IP",
        }

        if TCP in pkt:
            flow["protocol"] = "TCP"
            flow["src_port"] = pkt[TCP].sport
            flow["dst_port"] = pkt[TCP].dport

        return flow



    def run(self):
        self.nfqueue.bind(self.queue_num, self._process_packet)

        print(f"[+] NFQUEUE in ascolto su coda {self.queue_num}")

        try:
            self.nfqueue.run()
        except KeyboardInterrupt:
            print("\n[+] Stop emitter")
            self.nfqueue.unbind()
    
    
    
    def get_feedback(self):
        return self.feedback_analyzer.wait_for_feedback()
            
