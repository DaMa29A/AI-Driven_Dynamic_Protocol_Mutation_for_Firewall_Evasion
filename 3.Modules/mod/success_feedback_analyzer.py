class SuccessFeedbackAnalyzer:
    """
    Converte risultati del TrafficEmitter in verdict + reward.
    """

    def __init__(self):
        pass
    
    def analyze_http_result(self, result: dict) -> dict:
        """
        Analizza output di TrafficEmitter.send_http_request().
        """

        if result is None:
            return self._feedback(
                verdict="UNKNOWN",
                reward=-1.0,
                reason="HTTP result is None"
            )

        ok = result.get("ok")
        status_code = result.get("status_code")
        error = result.get("error")

        if ok is True and status_code is not None:
            return self._feedback(
                verdict="PASS",
                reward=1.0,
                reason=f"HTTP status {status_code}"
            )
            
        if ok is False:
            return self._feedback(
                verdict="BLOCK",
                reward=-1.0,
                reason=f"Error: {error}"
            )
            


    
    def analyze_packet_result(self, result: dict) -> dict:
        """
        Analizza output di TrafficEmitter.send_packet_and_classify().
        """

        if result is None:
            return self._feedback(
                verdict="UNKNOWN",
                reward=-1.0,
                reason="Packet result is None"
            )

        classification = result.get("classification", {})
        packet_result = classification.get("result")

        if packet_result == "SYN_ACK":
            return self._feedback(
                verdict="PASS",
                reward=1.0,
                reason=f"Received {packet_result}"
            )
        else :
            return self._feedback(
                verdict="BLOCK",
                reward=-1.0,
                reason=f"Received {packet_result}"
            )
    
    
    
    def _feedback(self, verdict: str, reward: float, reason: str) -> dict:
        #print(f"verdict: {verdict} - reward: {reward} - reason: {reason}")
        return {
            "verdict": verdict,
            "reward": reward,
            "reason": reason
        }
    
    
    def analyze_result(self, result: dict):
        type = result.get("type")
        if type == "pkt":
            return self.analyze_packet_result(result)
        if type == "http":
            return self.analyze_http_result(result)
