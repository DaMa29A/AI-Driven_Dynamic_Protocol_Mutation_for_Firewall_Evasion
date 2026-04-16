from scapy.all import IP, TCP, UDP, Raw, wrpcap


class ProtocolMutationGenerator:
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
    
    def generate_from_llm_strategy(self, json_packet_fields):
        pkt = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port)

        #1. Iteriamo sui campi suggeriti dall'LLM
        for key, value in json_packet_fields.items():
            if key.startswith("IP."):
                field_name = key.split(".")[1]
                setattr(pkt[IP], field_name, value)
            elif key.startswith("TCP."):
                field_name = key.split(".")[1]
                setattr(pkt[TCP], field_name, value)
        return pkt

        
    def generate_ttl_mutations(self, ttl_values):
        """
        Genera pacchetti TCP mutati variando il TTL.
        Output: crafted_packets (lista di pacchetti Scapy)
        """
        crafted_packets = []

        for ttl in ttl_values:
            tcp_pkt = (
                IP(src=self.src_ip, dst=self.dst_ip, ttl=ttl) /
                TCP(sport=self.src_port, dport=self.dst_port, flags="S")
                # Raw(load=f"ttl-{ttl}".encode()) # payload
            )

            crafted_packets.append(tcp_pkt)

        return crafted_packets

    def save_to_pcap(self, crafted_packets, filename):
        """
        Output secondario opzionale (debug/analisi)
        """
        wrpcap(filename, crafted_packets)