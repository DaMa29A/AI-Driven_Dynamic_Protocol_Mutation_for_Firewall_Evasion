import requests
from scapy.all import TCP, sr1, conf


class TrafficEmitter:
    def __init__(self, timeout=2, verbose=False, verify_tls=False):
        self.timeout = timeout
        self.verbose = verbose
        self.verify_tls = verify_tls
        conf.verb = 0 if not verbose else 1

    def send_packet(self, pkt):
        """
        Invia un pacchetto Scapy già costruito/mutato.
        """
        return sr1(
            pkt,
            timeout=self.timeout,
            verbose=self.verbose
        )

    def send_http_request(self, url, method="GET", headers=None):
        """
        Invia una richiesta HTTP/HTTPS.
        Utile per mutazioni applicative come User-Agent.
        """
        headers = headers or {}

        try:
            if method.upper() == "GET":
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_tls
                )
            elif method.upper() == "HEAD":
                response = requests.head(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_tls
                )
            else:
                raise ValueError(f"Metodo HTTP non supportato: {method}")

            return {
                "type": "http",
                "ok": True,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "headers": dict(response.headers),
                "error": None
            }

        except requests.exceptions.RequestException as exc:
            return {
                "type": "http",
                "ok": False,
                "status_code": None,
                "content_length": 0,
                "headers": {},
                "error": str(exc)
            }

    def classify_packet_response(self, response):
        if response is None:
            return {
                "result": "TIMEOUT",
                "meaning": "No response received"
            }

        if response.haslayer(TCP):
            flags = response[TCP].flags

            if flags & 0x12 == 0x12:
                return {
                    "result": "SYN_ACK",
                    "meaning": "TCP port open / packet passed"
                }

            if flags & 0x14 == 0x14:
                return {
                    "result": "RST_ACK",
                    "meaning": "TCP reset received"
                }

            return {
                "result": str(flags),
                "meaning": "Other TCP response"
            }

        return {
            "result": "UNKNOWN",
            "meaning": response.summary()
        }

    def send_packet_and_classify(self, pkt):
        response = self.send_packet(pkt)
        classification = self.classify_packet_response(response)

        return {
            "type": "pkt",
            "response": response,
            "classification": classification
        }