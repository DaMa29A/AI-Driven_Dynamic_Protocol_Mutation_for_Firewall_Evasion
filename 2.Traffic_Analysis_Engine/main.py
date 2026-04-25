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
    inter_arrival_times = []
    tcp_flags = []
    tcp_options = []

    last_time = None 
    error_printed = False # Usato per non spammare la console con lo stesso errore 2000 volte

    # Estrazione delle caratteristiche dai pacchetti
    for pkt in packets:
        try:
            # 1. Packet Size (Messo come prima istruzione per sicurezza)
            packet_sizes.append(len(pkt))

            # 2. Inter-packet timing (Controllo sicuro del timestamp)
            if hasattr(pkt, 'time') and pkt.time is not None:
                current_time = float(pkt.time)
                if last_time is not None:
                    diff = round(current_time - last_time, 6)
                    inter_arrival_times.append(diff)
                last_time = current_time

            # 3. Livello IP
            if IP in pkt:                   
                ttl_values.append(int(pkt[IP].ttl)) 

            # 4. Livello TCP
            if TCP in pkt:                  
                tcp_window_sizes.append(int(pkt[TCP].window)) 
                tcp_flags.append(str(pkt[TCP].flags))
                
                # Estrazione sicura delle opzioni TCP
                if hasattr(pkt[TCP], 'options') and pkt[TCP].options:
                    # Assicuriamoci che opt[0] sia sempre letto come stringa
                    opt_names = [str(opt[0]) for opt in pkt[TCP].options]
                    tcp_options.append(str(opt_names))
                else:
                    tcp_options.append("None")

        except Exception as e:
            # Stampiamo l'errore la prima volta che si verifica per capire cosa sta fallendo
            if not error_printed:
                print(f"[!] Attenzione: errore interno durante il parsing del pacchetto: {e}")
                error_printed = True
            continue
    
    # Arrotondamento per raggruppare i tempi inter-arrivo e calcolare le top_frequencies
    inter_arrival_rounded = [round(t, 3) for t in inter_arrival_times]

    # Costruzione del dizionario di analisi con statistiche e frequenze
    analysis = {
        "input_file": Path(pcap_path).name,
        "total_packets": len(packets),
        "features": {
            "packet_size": {
                "stats": safe_numeric_stats(packet_sizes),
                "top_values": top_frequencies(packet_sizes)
            },
            "inter_arrival_time": {
                "stats": safe_numeric_stats(inter_arrival_times),
                "top_values": top_frequencies(inter_arrival_rounded)
            },
            "ttl": {
                "stats": safe_numeric_stats(ttl_values),
                "top_values": top_frequencies(ttl_values)
            },
            "tcp": {
                "window_size": {
                    "stats": safe_numeric_stats(tcp_window_sizes),
                    "top_values": top_frequencies(tcp_window_sizes)
                },
                "flags_combinations": {
                    "top_values": top_frequencies(tcp_flags)
                },
                "options_combinations": {
                    "top_values": top_frequencies(tcp_options)
                }
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