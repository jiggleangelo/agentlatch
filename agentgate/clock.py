import time
from typing import Protocol

class Clock(Protocol):
    def now(self) -> int: ...

class SystemClock:
    def now(self) -> int:
        return int(time.time())

class FakeClock:
    def __init__(self, value: int = 1761300000): self.value = value
    def now(self) -> int: return self.value
    def advance(self, seconds: int) -> None: self.value += seconds
