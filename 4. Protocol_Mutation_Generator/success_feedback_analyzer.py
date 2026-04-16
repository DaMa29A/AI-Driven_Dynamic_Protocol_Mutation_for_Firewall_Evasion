import redis
import json

class SuccessFeedbackAnalyzer:
    def __init__(self):
        #self.redis = redis.Redis(host="localhost", port=6379, decode_responses=True)
        pass

    def analyze_result(self, response: str) -> int:
        """
        Restituisce:
        +1 se la risposta indica successo
        -1 altrimenti
        """
        if not response:
            return -1

        response = response.strip().lower()

        if "accepted" in response:
            return +1

        return -1


    def analyze_batch(self, results):
        """
        results: lista di tuple (packet, response)
        ritorna una lista di tuple (packet, response, reward)
        """
        analyzed = []

        for i, (packet, response) in enumerate(results):
            reward = self.analyze_result(response)

            data = {
                "packet": str(packet),
                "response": response,
                "reward": reward
            }

            # salva su Redis
            #self.redis.set(f"packet:{i}", json.dumps(data))

            analyzed.append((packet, response, reward))

        return analyzed