import base64
import hashlib
import json
import math
import secrets
import threading
from .keys import KeyRing


class TokenError(Exception):
    pass


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def b64d(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 16384:
        raise ValueError("invalid encoding")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def argument_hash(tool, args):
    try:
        raw = json.dumps({"tool": tool, "args": args}, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise TokenError("invalid_arguments") from exc
    return hashlib.sha256(raw).hexdigest()


class TokenService:
    def __init__(self, keys, registry, clock, issuer="agentgate-local", connector_keys=None):
        self.keys = keys
        self.connector_keys = connector_keys or KeyRing()
        self.registry = registry
        self.clock = clock
        self.issuer = issuer
        self.denied_jtis: set[str] = set()
        self._used_connector_jtis: set[str] = set()
        self._lock = threading.Lock()

    def _issue_with(self, keys, agent, scopes, ttl, audience, extra=None):
        ttl = max(1, min(int(ttl), 300))
        now = self.clock.now()
        kid = keys.active_kid
        payload = {
            "v": 1,
            "kid": kid,
            "iss": self.issuer,
            "aud": audience,
            "sub": agent.agent_id,
            "scp": sorted(set(scopes)),
            "iat": now,
            "exp": now + ttl,
            "jti": secrets.token_hex(16),
        }
        payload.update(extra or {})
        encoded = b64e(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        message = ("agt1." + encoded).encode()
        _, signature = keys.sign(message, kid)
        return "agt1." + encoded + "." + b64e(signature), payload

    def issue(self, agent, scopes, ttl=300, audience="agentgate-local"):
        if audience != "agentgate-local":
            raise TokenError("invalid_audience")
        return self._issue_with(self.keys, agent, scopes, ttl, audience)

    def issue_connector_assertion(self, agent, tool, args, ttl=30):
        audience = "connector:" + tool
        return self._issue_with(
            self.connector_keys,
            agent,
            [tool],
            min(int(ttl), 30),
            audience,
            {"arg_hash": argument_hash(tool, args)},
        )

    def _decode_verified(self, token, keys):
        try:
            if not isinstance(token, str) or len(token) > 32768:
                raise ValueError
            version, encoded, signature = token.split(".")
            if version != "agt1":
                raise ValueError
            raw = b64d(encoded)
            preliminary = json.loads(raw)
            kid = preliminary.get("kid")
            if not isinstance(kid, str) or not keys.verify(kid, (version + "." + encoded).encode(), b64d(signature)):
                raise TokenError("invalid_token")
            payload = json.loads(raw)
        except TokenError:
            raise
        except Exception as exc:
            raise TokenError("invalid_token") from exc
        return payload

    def _validate(self, payload, audience):
        try:
            if payload.get("v") != 1 or payload.get("iss") != self.issuer or payload.get("aud") != audience:
                raise TokenError("invalid_token")
            exp = payload.get("exp")
            iat = payload.get("iat")
            if isinstance(exp, bool) or isinstance(iat, bool) or not isinstance(exp, (int, float)) or not isinstance(iat, (int, float)):
                raise TokenError("invalid_token")
            if not math.isfinite(exp) or not math.isfinite(iat) or exp < iat or exp - iat > 300:
                raise TokenError("invalid_token")
            if self.clock.now() > exp + 5:
                raise TokenError("invalid_token")
            if not isinstance(payload.get("jti"), str) or not isinstance(payload.get("scp"), list):
                raise TokenError("invalid_token")
        except TokenError:
            raise
        except Exception as exc:
            raise TokenError("invalid_token") from exc
        agent = self.registry.get(payload.get("sub", ""))
        if not agent or agent.revoked or payload["jti"] in self.denied_jtis:
            raise TokenError("invalid_token")
        return payload

    def verify(self, token: str, audience="agentgate-local") -> dict:
        if audience != "agentgate-local":
            raise TokenError("invalid_token")
        return self._validate(self._decode_verified(token, self.keys), audience)

    def verify_connector_assertion(self, token, tool, args):
        payload = self._validate(self._decode_verified(token, self.connector_keys), "connector:" + tool)
        if tool not in payload["scp"] or payload.get("arg_hash") != argument_hash(tool, args):
            raise TokenError("invalid_token")
        with self._lock:
            if payload["jti"] in self._used_connector_jtis:
                raise TokenError("replayed_assertion")
            self._used_connector_jtis.add(payload["jti"])
        return payload

    def revoke(self, token_or_jti):
        if isinstance(token_or_jti, str) and token_or_jti.startswith("agt1."):
            payload = self._decode_verified(token_or_jti, self.keys)
            jti = payload.get("jti")
        else:
            jti = token_or_jti
        if not isinstance(jti, str) or not jti:
            raise TokenError("invalid_token")
        self.denied_jtis.add(jti)

    def exchange(self, agent, requested, permitted, ttl=300):
        if not isinstance(requested, (list, tuple, set)) or any(not isinstance(scope, str) for scope in requested):
            raise TokenError("invalid_scope")
        scopes = sorted(set(requested) & set(permitted))
        if not scopes:
            raise TokenError("invalid_scope")
        return self.issue(agent, scopes, ttl)
