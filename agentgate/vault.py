from abc import ABC, abstractmethod
import secrets

class Vault(ABC):
    @abstractmethod
    def put(self, kind: str, value: str) -> str: ...

class SealedMemoryVault(Vault):
    def __init__(self): self.__entries = {}
    def put(self, kind, value):
        ref = "vref_" + secrets.token_hex(12)
        self.__entries[ref] = (kind, value)
        return ref
    def __repr__(self): return "SealedMemoryVault(<sealed>)"
