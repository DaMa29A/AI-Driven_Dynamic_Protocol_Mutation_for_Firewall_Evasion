"""
Il TrafficEmitter registra cosa ha mutato
Quando modifica un pacchetto, salva almeno:
sorgente IP
destinazione IP
sorgente porta
destinazione porta
protocollo
timestamp
TTL applicato

Il SuccessFeedbackAnalyzer sniffa
Poi guarda i pacchetti in arrivo e verifica se matchano il flusso inverso:
src_ip == dst_ip_originale
dst_ip == src_ip_originale
src_port == dst_port_originale
dst_port == src_port_originale
Se sì, quella è una risposta associabile a quel flusso.
"""

import time
from threading import Lock
from scapy.all import AsyncSniffer, IP, TCP, ICMP


class SuccessFeedbackAnalyzer:
    def __init__(self, iface="eth0", timeout=5):
        self.iface = iface
        self.timeout = timeout
        self.last_flow = None
        self._lock = Lock()

    def register_outgoing_flow(self, flow_info: dict):
        with self._lock:
            self.last_flow = {
                **flow_info,
                "ts": time.time()
            }

    def _get_last_flow(self):
        with self._lock:
            return self.last_flow

    def _matches_reverse_flow(self, pkt, flow: dict) -> bool:
        if IP not in pkt:
            return False

        if pkt[IP].src != flow["dst_ip"]:
            return False
        if pkt[IP].dst != flow["src_ip"]:
            return False

        if flow["protocol"] == "TCP":
            if TCP not in pkt:
                return False
            if pkt[TCP].sport != flow["dst_port"]:
                return False
            if pkt[TCP].dport != flow["src_port"]:
                return False

        return True

    def _classify_packet(self, pkt, flow: dict):
        if not self._matches_reverse_flow(pkt, flow):
            return None

        if TCP in pkt:
            tcp = pkt[TCP]

            if tcp.flags & 0x04:
                return {
                    "result": "RST_SEEN",
                    "reward": -1,
                    "details": "TCP reset"
                }

            return {
                "result": "RESPONSE_SEEN",
                "reward": 1,
                "details": "TCP response"
            }

        if ICMP in pkt:
            icmp = pkt[ICMP]
            return {
                "result": "ICMP_SEEN",
                "reward": -1,
                "details": f"ICMP type={icmp.type} code={icmp.code}"
            }

        return None

    def wait_for_feedback(self):
        start = time.time()

        # 1. parto subito a sniffare
        sniffer = AsyncSniffer(iface=self.iface, store=True)
        sniffer.start()

        try:
            # 2. aspetto che il flow venga registrato
            flow = None
            flow_deadline = time.time() + 2.0
            while time.time() < flow_deadline:
                flow = self._get_last_flow()
                if flow is not None:
                    break
                time.sleep(0.01)

            print(f"Last flow:\n{flow}")

            if not flow:
                sniffer.stop()
                return {
                    "result": "NO_FLOW",
                    "reward": -1,
                    "latency_s": round(time.time() - start, 3)
                }

            # 3. continuo a catturare per la finestra utile
            time.sleep(self.timeout)

            packets = sniffer.stop()

            for pkt in packets:
                classified = self._classify_packet(pkt, flow)
                if classified:
                    classified["latency_s"] = round(time.time() - start, 3)
                    return classified

            return {
                "result": "NO_RESPONSE",
                "reward": -1,
                "latency_s": round(time.time() - start, 3)
            }

        finally:
            try:
                sniffer.stop()
            except Exception:
                pass