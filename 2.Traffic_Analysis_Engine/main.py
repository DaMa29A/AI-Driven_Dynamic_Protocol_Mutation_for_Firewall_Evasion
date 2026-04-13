import json
import sys
from pathlib import Path
from scapy.all import rdpcap, IP, TCP
from constants import INPUT_PCAP, OUTPUT_JSON
from utils import safe_numeric_stats, top_frequencies


def analyze_pcap(pcap_path):
    packets = rdpcap(str(pcap_path)) # Caricamento dei pacchetti dal file pcap

    packet_sizes = []
    ttl_values = []
    tcp_window_sizes = []

    # Estrazione delle caratteristiche dai pacchetti
    for pkt in packets:
        try:
            packet_sizes.append(len(pkt))   # Dimensione totale del pacchetto

            if IP in pkt:                   # Solo se il pacchetto ha un livello IP
                ttl_values.append(int(pkt[IP].ttl)) # Valore TTL del pacchetto IP

            if TCP in pkt:                  # Solo se il pacchetto ha un livello TCP
                tcp_window_sizes.append(int(pkt[TCP].window)) # Valore della finestra TCP

        except Exception:
            continue
    
    # Costruzione del dizionario di analisi con statistiche e frequenze
    analysis = {
        "input_file": Path(pcap_path).name,
        "total_packets": len(packets),
        "features": {
            "packet_size": {
                "stats": safe_numeric_stats(packet_sizes),
                "top_values": top_frequencies(packet_sizes)
            },
            "ttl": {
                "stats": safe_numeric_stats(ttl_values),
                "top_values": top_frequencies(ttl_values)
            },
            "tcp_window_size": {
                "stats": safe_numeric_stats(tcp_window_sizes),
                "top_values": top_frequencies(tcp_window_sizes)
            }
        }
    }

    return analysis


def main():
    print("[+] Inizio analisi.")
    try:
        result = analyze_pcap(INPUT_PCAP)

        with open(str(OUTPUT_JSON), "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        print("[+] Analisi completata.")
        print(f"[+] Pacchetti analizzati: {result['total_packets']}")

    except FileNotFoundError:
        print(f"[!] File non trovato: {INPUT_PCAP}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"[!] Errore durante l'analisi: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()