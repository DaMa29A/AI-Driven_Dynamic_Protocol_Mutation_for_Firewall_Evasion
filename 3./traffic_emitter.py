#!/usr/bin/env python3

import time
from scapy.all import send, sniff, IP, TCP, ICMP

# =========================
# CONFIGURAZIONE
# =========================
INTERFACE = "eth0"
SNIFF_TIMEOUT = 2
SNIFF_COUNT = 20
SEND_VERBOSE = False


class TrafficEmitter:
    def __init__(self, interface=INTERFACE, sniff_timeout=SNIFF_TIMEOUT, sniff_count=SNIFF_COUNT):
        self.interface = interface
        self.sniff_timeout = sniff_timeout
        self.sniff_count = sniff_count

    def build_bpf_filter(self, pkt):
        if IP not in pkt:
            return "tcp or icmp"

        dst_ip = pkt[IP].dst
        src_ip = pkt[IP].src

        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            # intercetta traffico tra i due endpoint e ICMP correlato
            return (
                f"host {src_ip} and host {dst_ip} and "
                f"(tcp port {sport} or tcp port {dport} or icmp)"
            )

        return f"host {src_ip} and host {dst_ip} and (tcp or icmp)"

    def classify_response(self, sent_pkt, responses):
        if IP not in sent_pkt or TCP not in sent_pkt:
            return {
                "result": "unknown",
                "details": {"reason": "sent packet is not IP/TCP"}
            }

        sent_src = sent_pkt[IP].src
        sent_dst = sent_pkt[IP].dst
        sent_sport = sent_pkt[TCP].sport
        sent_dport = sent_pkt[TCP].dport

        for resp in responses:
            if IP not in resp:
                continue

            # ICMP
            if ICMP in resp:
                return {
                    "result": "blocked_icmp",
                    "details": {
                        "icmp_type": resp[ICMP].type,
                        "icmp_code": resp[ICMP].code
                    }
                }

            # TCP
            if TCP in resp:
                resp_src = resp[IP].src
                resp_dst = resp[IP].dst
                resp_sport = resp[TCP].sport
                resp_dport = resp[TCP].dport
                resp_flags = str(resp[TCP].flags)

                # risposta inversa rispetto al pacchetto inviato
                same_flow_reverse = (
                    resp_src == sent_dst and
                    resp_dst == sent_src and
                    resp_sport == sent_dport and
                    resp_dport == sent_sport
                )

                if not same_flow_reverse:
                    continue

                if "R" in resp_flags:
                    return {
                        "result": "blocked_rst",
                        "details": {
                            "tcp_flags": resp_flags
                        }
                    }

                if "S" in resp_flags and "A" in resp_flags:
                    return {
                        "result": "passed_synack",
                        "details": {
                            "tcp_flags": resp_flags
                        }
                    }

                if "A" in resp_flags:
                    return {
                        "result": "passed_ack",
                        "details": {
                            "tcp_flags": resp_flags
                        }
                    }

                return {
                    "result": "passed_other_tcp",
                    "details": {
                        "tcp_flags": resp_flags
                    }
                }

        return {
            "result": "timeout",
            "details": {}
        }

    def emit_packet(self, pkt):
        bpf_filter = self.build_bpf_filter(pkt)

        #send(pkt, iface=self.interface, verbose=SEND_VERBOSE)
        send(pkt, verbose=SEND_VERBOSE)

        responses = sniff(
            iface=self.interface,
            filter=bpf_filter,
            timeout=self.sniff_timeout,
            count=self.sniff_count
        )

        classification = self.classify_response(pkt, responses)

        return {
            "sent_packet": pkt,
            "result": classification["result"],
            "details": classification["details"],
            "sniffed_packets_count": len(responses),
            "timestamp": time.time()
        }

    def emit_mutation(self, mutation):
        pkt = mutation["packet"]
        emit_result = self.emit_packet(pkt)

        return {
            "mutation_type": mutation.get("mutation_type"),
            "original_value": mutation.get("original_value"),
            "mutated_value": mutation.get("mutated_value"),
            "result": emit_result["result"],
            "details": emit_result["details"],
            "sniffed_packets_count": emit_result["sniffed_packets_count"],
            "timestamp": emit_result["timestamp"]
        }

    def emit_mutations(self, mutations, delay=0.5):
        results = []

        for idx, mutation in enumerate(mutations, start=1):
            result = self.emit_mutation(mutation)
            results.append(result)

            print(
                f"[+] Mutation {idx}/{len(mutations)} | "
                f"{result['mutation_type']} "
                f"{result['original_value']} -> {result['mutated_value']} | "
                f"result={result['result']}"
            )

            time.sleep(delay)

        return results