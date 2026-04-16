def _build_prompt(self):
        #protocols = ["TCP", "HTTP", "TLS"]
        protocols = ["TCP"]

        total_packets = self.baseline.get("total_packets", "N/A")
        min_dim_packet = self.baseline.get("features", {}).get("packet_size", {}).get("stats", {}).get("min")
        max_dim_packet = self.baseline.get("features", {}).get("packet_size", {}).get("stats", {}).get("max")
        min_ttl = self.baseline.get("features", {}).get("ttl", {}).get("stats", {}).get("min")
        max_ttl = self.baseline.get("features", {}).get("ttl", {}).get("stats", {}).get("max")
        min_tcp_win_size = self.baseline.get("features", {}).get("tcp_window_size", {}).get("stats", {}).get("min")
        max_tcp_win_size = self.baseline.get("features", {}).get("tcp_window_size", {}).get("stats", {}).get("max")

        # Level 3
        #fields_ip_to_mutate = ["ttl", "tos", "flags", "options", "frag", "id"]
        fields_ip_to_mutate = ["ttl"]
        # Level 4
        #fields_tcp_to_mutate = ["seq", "ack", "window", "flags", "options"]
        fields_tcp_to_mutate = ["window"]
        # Level 7
        fields_http_to_mutate = ["User-Agent", "Accept", "Accept-Language", "Host", "Connection", "Content-Length", "Cookie"]
        
        prompt = (
            'Sei un esperto di cybersecurity (Red Teamer).\n'
            'Obiettivo:'
            'Analizzare un baseline profile di traffico legittimo '
            'e generare UNA sola strategia tecnica realistica mirata per evadere un firewall pfSense con Suricata/Snort '
            'che usa regole pubbliche (Emerging Threats).\n\n'

            'Baseline profile che devi ANALIZZARE e a cui devi far riferimento per mutazioni:\n'
            f'"total_packets": {total_packets}\n'
            f'"min_dim_packet": {min_dim_packet}\n'
            f'"max_dim_packet": {max_dim_packet}\n'
            f'"min_ttl": {min_ttl}\n'
            f'"max_ttl": {max_ttl}\n'
            f'"min_tcp_win_size": {min_tcp_win_size}\n'
            f'"max_tcp_win_size": {max_tcp_win_size}\n\n'

            'Protocolli consentiti:\n'
            f'{protocols}\n\n'

            'UNICI campi che puoi modificare:\n'
            'Campi IP:\n'
            f'{fields_ip_to_mutate}\n'
            'Campi TCP:\n'
            f'{fields_tcp_to_mutate}\n\n'

            'Vincoli obbligatori:\n'
            '1. Le mutazioni devono essere conformi al protocollo.\n'
            '2. Puoi usare più pacchetti per implementare la strategia.\n'
            '3. Devi specificarfe tutti i campi del pacchetto o dei pacchetti da costruire con Scapy.\n'
            '4. NON includere IP sorgente/destinazione e porte.\n'
            '5. Usa prefissi: "IP.xxx", "TCP.xxx".\n'
            '6. Devi includere un profilo di traffico realistico per i pacchetti che mi fornisci: timing, jitter, rate, ritrasmissioni.\n'
            '7. Devi rispondere ESCLUSIVAMENTE con JSON valido.\n'
            '8. Non aggiungere testo prima o dopo il JSON.\n\n'
            
            'Schema JSON obbligatorio che DEVI seguire sempre:\n'
            '{\n'       
            '    "protocol": "TCP|HTTP|TLS",\n'
            '    "strategy_name": "Nome sintetico che riassume strategia",\n'
            '    "reasoning": "Una breve descrizione del perchè sarebbe utile usare questa strategia e perchè è in linea con baseline",\n'
            '    "packet_count": int,\n'
            '    "traffic_profile": {\n'
            '        "inter_packet_delay_ms": [int],\n' 
            '        "jitter_ms": int,\n'
            '        "retransmissions": int,\n'
            '        "packet_order": "sequential|shuffled",\n' 
            '        "rate_pps": int\n'
            '    },\n'
            '    "packets": [\n'
            '        {\n'
            '            "IP.ttl": int,\n'
            '            "IP.tos": int,\n'
            '            "TCP.flags": "S|A|PA|...",\n'
            '            "TCP.window": int,\n'
            '             ...\n'
            '        },\n'
            '        ...\n'
            '     ]\n' 
            '}\n'               
        )

        # if not self.history:
        #     prompt += "- Nessun tentativo ancora effettuato.\n"
        # else:
        #     for attempt in self.history:
        #         status = "PASSATO (+1)" if attempt['reward'] == 1 else "BLOCCATO (-1)"
        #         prompt += f"- Valore testato: {attempt['value']} -> Esito: {status}\n"

        # prompt += (
        #     "\nAnalizza la situazione con un ragionamento passo-passo (Chain-of-Thought).\n"
        #     "Proponi una nuova mutazione che rimanga verosimile rispetto alla baseline ma che eviti il blocco.\n"
        #     f"Fornisci il valore numerico finale per il campo {field_to_mutate} tra parentesi quadre, ad esempio: [128]."
        # )
        return prompt