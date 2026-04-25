from scapy.all import IP, TCP
from mitmproxy import http
from .utils import load_json
from mod.constants import OUTPUT_STRATEGY_JSON


class ProtocolMutationGenerator:
    def __init__(self, strategy=None):
        self.strategy = strategy or {}
    
    def add_strategy(self, strategy=None):
        if strategy is not None:
            self.strategy = strategy 
        else: 
            self.strategy = load_json(OUTPUT_STRATEGY_JSON)
        
        
    def mutate_ttl(self, pkt, new_ttl):
        mutated_pkt = pkt.copy()

        if IP in mutated_pkt:
            mutated_pkt[IP].ttl = int(new_ttl)

        return self.clone_and_recalc(mutated_pkt)

    def mutate_window_size(self, pkt, new_window):
        mutated_pkt = pkt.copy()

        if TCP in mutated_pkt:
            mutated_pkt[TCP].window = int(new_window)

        return self.clone_and_recalc(mutated_pkt)

    def mutate_user_agent_req(self, flow: http.HTTPFlow, user_agent: str):
        old_ua = flow.request.headers.get("User-Agent", None)
        flow.request.headers["User-Agent"] = user_agent

        return {
            "flow": flow,
            "old_user_agent": old_ua,
            "new_user_agent": user_agent
        }

    def apply_packet_strategy(self, pkt, strategy: dict):
        mutated_pkt = pkt.copy()

        if "ttl" in strategy:
            mutated_pkt = self.mutate_ttl(mutated_pkt, strategy["ttl"])

        if "tcp_window" in strategy:
            mutated_pkt = self.mutate_window_size(
                mutated_pkt,
                strategy["tcp_window"]
            )

        return self.clone_and_recalc(mutated_pkt)

    def apply_http_strategy(self, flow: http.HTTPFlow, strategy: dict):
        mutation_log = {}

        if "user_agent" in strategy:
            mutation_log["user_agent"] = self.mutate_user_agent_req(
                flow,
                strategy["user_agent"]
            )

        return flow, mutation_log

    def clone_and_recalc(self, pkt):
        p = pkt.copy()

        if IP in p:
            if hasattr(p[IP], "len"):
                del p[IP].len
            if hasattr(p[IP], "chksum"):
                del p[IP].chksum

        if TCP in p:
            if hasattr(p[TCP], "chksum"):
                del p[TCP].chksum

        return p