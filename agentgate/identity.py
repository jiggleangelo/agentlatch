from dataclasses import dataclass
import hashlib
import hmac
import re
import secrets
import threading


class AuthError(Exception):
    pass


@dataclass
class Agent:
    agent_id: str
    name: str
    secret_hash: bytes
    salt: bytes
    created_at: int
    revoked: bool = False


class AgentRegistry:
    # HTTP worker concurrency bounds the number of waiters. Waiting briefly here
    # avoids turning ordinary contention into immediate identity_busy failures.
    _hash_slots = threading.BoundedSemaphore(2)
    HASH_WAIT_SECONDS = 2.0
    ITERATIONS = 200_000

    def __init__(self, clock, limit=50, auth_fail_limit=10):
        self.clock = clock
        self.limit = limit
        self.auth_fail_limit = auth_fail_limit
        self.agents = {}
        self._failures = {}
        self._lock = threading.RLock()
        self._dummy_salt = secrets.token_bytes(16)
        self._dummy_hash = secrets.token_bytes(32)

    @classmethod
    def _hash(cls, secret, salt):
        if not cls._hash_slots.acquire(timeout=cls.HASH_WAIT_SECONDS):
            raise RuntimeError('identity_busy')
        try:
            return hashlib.pbkdf2_hmac('sha256', secret.encode(), salt, cls.ITERATIONS)
        finally:
            cls._hash_slots.release()

    def register(self, name):
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9 ._-]{1,64}', name):
            raise ValueError('invalid_name')
        with self._lock:
            if len(self.agents) >= self.limit:
                raise ValueError('agent_limit')
            if any(agent.name == name for agent in self.agents.values()):
                raise ValueError('duplicate_name')
            secret = 'ags_' + secrets.token_urlsafe(24)
            salt = secrets.token_bytes(16)
            digest = self._hash(secret, salt)
            agent = Agent('agt_' + secrets.token_hex(8), name, digest, salt, self.clock.now())
            self.agents[agent.agent_id] = agent
            return agent, secret

    def authenticate(self, client_id, secret, source='local'):
        if not isinstance(client_id, str) or not isinstance(secret, str) or not isinstance(source, str):
            raise AuthError('invalid client credentials')
        if not (1 <= len(client_id) <= 128 and 1 <= len(secret) <= 512 and len(source) <= 128):
            raise AuthError('invalid client credentials')
        minute = self.clock.now() // 60
        client_key = ('client', client_id, minute)
        source_key = ('source', source, minute)
        with self._lock:
            self._failures = {key: value for key, value in self._failures.items() if key[-1] >= minute - 1}
            if len(self._failures) >= 2048:
                raise AuthError('invalid client credentials')
            if self._failures.get(client_key, 0) >= self.auth_fail_limit or self._failures.get(source_key, 0) >= self.auth_fail_limit * 5:
                raise AuthError('invalid client credentials')
            self._failures[client_key] = self._failures.get(client_key, 0) + 1
            self._failures[source_key] = self._failures.get(source_key, 0) + 1
            agent = self.agents.get(client_id)
        candidate = self._hash(secret, agent.salt if agent else self._dummy_salt)
        matches = hmac.compare_digest(candidate, agent.secret_hash if agent else self._dummy_hash)
        with self._lock:
            valid = agent is not None and not agent.revoked and matches
            if valid:
                self._failures[client_key] = max(0, self._failures.get(client_key, 1) - 1)
                self._failures[source_key] = max(0, self._failures.get(source_key, 1) - 1)
        if not valid:
            raise AuthError('invalid client credentials')
        return agent

    def get(self, agent_id):
        if not isinstance(agent_id, str):
            return None
        with self._lock:
            return self.agents.get(agent_id)

    def revoke(self, agent_id):
        with self._lock:
            agent = self.agents.get(agent_id)
            if agent:
                agent.revoked = True
