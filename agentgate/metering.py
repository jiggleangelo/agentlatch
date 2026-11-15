import datetime

class Metering:
    def __init__(self, clock): self.clock, self._active = clock, set()
    def record(self, agent_id):
        month = datetime.datetime.fromtimestamp(self.clock.now(), datetime.UTC).strftime("%Y-%m")
        self._active.add((month, agent_id))
    def estimate(self):
        month = datetime.datetime.fromtimestamp(self.clock.now(), datetime.UTC).strftime("%Y-%m")
        active = sum(1 for m, _ in self._active if m == month)
        return max(500, 15 * active)
