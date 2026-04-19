import threading
import time

from scapy.all import IP
import subprocess
from traffic_emitter import TrafficEmitter

SRC_IP = "192.168.10.10"
DST_IP = "192.168.20.10"   
DST_PORT = 80

def run_curl(url):
    print(f"[+] Eseguo curl verso {url}")
    try:
        subprocess.run(["curl", f"http://{url}"], timeout=10)
    except subprocess.TimeoutExpired:
        print("[!] curl timeout")


if __name__ == "__main__":
    emitter = TrafficEmitter(
        queue_num=1
    )

    t_emitter = threading.Thread(target=emitter.run, daemon=True)
    t_emitter.start()

    time.sleep(2)

    feedback_box = {}

    def collect_feedback():
        feedback_box["result"] = emitter.get_feedback()

    # lo sniff parte PRIMA
    t_feedback = threading.Thread(target=collect_feedback)
    t_feedback.start()

    time.sleep(0.2)

    # poi generi traffico
    run_curl(DST_IP)

    t_feedback.join()

    print("\n[FEEDBACK]")
    print(feedback_box.get("result"))