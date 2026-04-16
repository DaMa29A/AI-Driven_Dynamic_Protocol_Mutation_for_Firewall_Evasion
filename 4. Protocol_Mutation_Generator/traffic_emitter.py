from scapy.all import send, sr1, IP, TCP, UDP, ICMP
import time


class TrafficEmitter:
    def __init__(self, timeout=2, inter_delay=0.1, verbose=True):
        """
        :param timeout: tempo di attesa per risposta
        :param inter_delay: delay tra pacchetti (simula traffico reale)
        :param verbose: stampa output
        """
        self.timeout = timeout
        self.inter_delay = inter_delay
        self.verbose = verbose

    def send_packets(self, packets):
        """
        Invia una lista di pacchetti e verifica se arrivano.

        :param packets: lista di pacchetti Scapy
        :return: lista risultati [(pkt, status)]
        """

        results = []

        for i, pkt in enumerate(packets):
            try:
                if self.verbose:
                    print(f"\n[+] Sending packet {i+1}: {pkt.summary()}")

                # invia e aspetta risposta (solo per protocolli che possono rispondere)
                response = sr1(pkt, timeout=self.timeout, verbose=0)

                status = self._analyze_response(response)

                if self.verbose:
                    print(f"[+] Result: {status}")

                results.append((pkt, status))

                time.sleep(self.inter_delay)

            except Exception as e:
                if self.verbose:
                    print(f"[!] Error sending packet: {e}")
                results.append((pkt, "error"))

        return results

    def _analyze_response(self, response):
        """
        Determina se il pacchetto è arrivato o bloccato.
        """

        if response is None:
            return "no_response (possible drop)"

        # ICMP error → probabilmente bloccato
        if response.haslayer(ICMP):
            return "blocked (ICMP)"

        # TCP response
        if response.haslayer(TCP):
            flags = response[TCP].flags

            if flags == 0x12:  # SYN-ACK
                return "accepted (SYN-ACK)"
            elif flags == 0x14:  # RST-ACK
                return "rejected (RST)"
            else:
                return f"tcp_response (flags={flags})"

        # UDP → spesso no risposta
        if response.haslayer(UDP):
            return "udp_response"

        return "unknown_response"