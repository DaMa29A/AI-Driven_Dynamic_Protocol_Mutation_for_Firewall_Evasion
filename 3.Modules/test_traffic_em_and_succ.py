from scapy.all import IP, TCP
from mod.traffic_emitter import TrafficEmitter
from mod.success_feedback_analyzer import SuccessFeedbackAnalyzer

'''
Per avviare:
sudo ./.venv/bin/python ./3.Modules/test_traffic_em_and_succ.py
'''


def print_result(title, result):
    print(f"\n=== {title} ===")
    print("Classification:", result["classification"])

    if result["response"] is not None:
        print("Raw response:")
        result["response"].summary()
    else:
        print("No response received")


def print_http_result(title, result):
    print(f"\n=== {title} ===")
    print("OK:", result["ok"])
    print("Status code:", result["status_code"])
    print("Content length:", result["content_length"])
    print("Error:", result["error"])


def main():
    target_ip = "192.168.20.10"
    base_url = f"http://{target_ip}"

    emitter = TrafficEmitter(timeout=2, verbose=False)
    sfa = SuccessFeedbackAnalyzer()

    print("[+] Inizio test TrafficEmitter")

    # -----------------------------
    # 1. SUCCESS (porta 80 aperta)
    # -----------------------------
    pkt_success = IP(dst=target_ip, ttl=64) / TCP(
        dport=80,
        flags="S",
        window=64240
    )

    res_success = emitter.send_packet_and_classify(pkt_success)
    print_result("TEST SUCCESS (porta 80)", res_success)
    print(sfa.analyze_result(res_success))

    # -----------------------------
    # 2. RST (porta chiusa)
    # -----------------------------
    pkt_rst = IP(dst=target_ip, ttl=64) / TCP(
        dport=9999,   # porta chiusa
        flags="S",
        window=64240
    )

    res_rst = emitter.send_packet_and_classify(pkt_rst)
    print_result("TEST RST (porta chiusa)", res_rst)
    print(sfa.analyze_result(res_rst ))

    # -----------------------------
    # 3. TIMEOUT (DROP simulato)
    # -----------------------------
    pkt_timeout = IP(dst=target_ip, ttl=64) / TCP(
        dport=22,   # porta probabilmente filtrata
        flags="S",
        window=64240
    )

    res_timeout = emitter.send_packet_and_classify(pkt_timeout)
    print_result("TEST TIMEOUT (drop/firewall)", res_timeout)
    print(sfa.analyze_result(res_timeout))
    
    
    
     # -----------------------------
    # 4. HTTP TEST: GET valido
    # -----------------------------
    headers_normal = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7"
    }

    res_http_ok = emitter.send_http_request(
        url=f"{base_url}/mfolder/index.html",
        method="GET",
        headers=headers_normal
    )

    print_http_result("HTTP TEST GET valido", res_http_ok)
    print(sfa.analyze_result(res_http_ok))

    # -----------------------------
    # 5. HTTP TEST: HEAD valido
    # -----------------------------
    res_http_head = emitter.send_http_request(
        url=f"{base_url}/mfolder/index.html",
        method="HEAD",
        headers=headers_normal
    )

    print_http_result("HTTP TEST HEAD valido", res_http_head)
    print(sfa.analyze_result(res_http_head))

    # -----------------------------
    # 6. HTTP TEST: path mancante
    # -----------------------------
    res_http_404 = emitter.send_http_request(
        url=f"{base_url}/mfolder/non-esiste.html",
        method="GET",
        headers=headers_normal
    )

    print_http_result("HTTP TEST GET path mancante", res_http_404)
    print(sfa.analyze_result(res_http_404))

    # -----------------------------
    # 7. HTTP TEST: User-Agent mutato
    # -----------------------------
    headers_mutated = {
        "User-Agent": "curl/7.68.0",
        "Accept-Language": "en-US,en;q=0.9"
    }

    res_http_ua = emitter.send_http_request(
        url=f"{base_url}/mfolder/index.html",
        method="GET",
        headers=headers_mutated
    )

    print_http_result("HTTP TEST User-Agent mutato", res_http_ua)
    print(sfa.analyze_result(res_http_ua))
    
    # -----------------------------
    # 8. Host inesistente
    # -----------------------------
    res_http_timeout = emitter.send_http_request(
        url="http://192.168.20.99/mfolder/index.html",  # IP inesistente
        method="GET",
        headers=headers_normal
    )

    print_http_result("HTTP TEST TIMEOUT (host inesistente)", res_http_timeout)
    print(sfa.analyze_result(res_http_timeout))

    print("\n[+] Test completato")


if __name__ == "__main__":
    main()