from dataclasses import asdict, dataclass, replace
import hashlib
import hmac
import json
import re
import secrets
import threading


@dataclass(frozen=True)
class Entry:
    index: int
    ts: int
    event: str
    agent_id: str
    tool: str | None
    decision: str
    reason: str
    args: dict
    prev_hash: str
    hash: str


class AuditLog:
    """Bounded HMAC chain with bounded, redacted entries and cached verification."""

    ARG_NAMES = frozenset({'amount', 'currency', 'order_id', 'account_id', 'path'})
    MAX_ENTRY_BYTES = 8192
    MAX_CONTAINER_ITEMS = 16
    MAX_NODES = 128
    MAX_DEPTH = 8

    def __init__(self, clock, limit=2000, chain_key=None, digest_key=None, tool_names=()):
        self.clock = clock
        self.limit = limit
        self._digest_key = digest_key or secrets.token_bytes(32)
        self._chain_key = chain_key or secrets.token_bytes(32)
        self._lock = threading.RLock()
        self.tool_names = frozenset(tool_names)
        self.entries = []
        self._version = 0
        self._verify_cache_version = 0
        self._verify_cache = (True, None)

    def _digest(self, value):
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str)
        return 'hmac:' + hmac.new(self._digest_key, raw.encode(), hashlib.sha256).hexdigest()[:24]

    @staticmethod
    def _path_withheld(path, withheld):
        return any(path[:len(item)] == item for item in withheld)

    def _digest_value(self, value, path, withheld, budget, depth=0):
        if self._path_withheld(path, withheld):
            return '<withheld>'
        if budget[0] <= 0 or depth > self.MAX_DEPTH:
            return '<truncated>'
        budget[0] -= 1
        if isinstance(value, dict):
            output = {}
            for index, (key, child) in enumerate(value.items()):
                if index >= self.MAX_CONTAINER_ITEMS or budget[0] <= 0:
                    output['<truncated>'] = '<truncated>'
                    break
                text_key = str(key)
                child_path = path + (text_key,)
                if self._path_withheld(child_path, withheld):
                    label, redacted = f'<withheld-key-{index}>', '<withheld>'
                else:
                    label = text_key if text_key in self.ARG_NAMES else self._digest(text_key)
                    redacted = self._digest_value(child, child_path, withheld, budget, depth + 1)
                output[label] = redacted
            return output
        if isinstance(value, (list, tuple)):
            output = [self._digest_value(child, path + (str(index),), withheld, budget, depth + 1)
                      for index, child in enumerate(value[:self.MAX_CONTAINER_ITEMS])]
            if len(value) > self.MAX_CONTAINER_ITEMS:
                output.append('<truncated>')
            return output
        return self._digest(value)

    @staticmethod
    def _safe_text(value, maximum=128):
        text = value if isinstance(value, str) else str(value)
        return text[:maximum]

    def _hash(self, data):
        encoded = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
        return hmac.new(self._chain_key, encoded, hashlib.sha256).hexdigest()

    def append(self, event, agent_id, tool=None, decision='n/a', reason='', args=None, withheld=None):
        with self._lock:
            if len(self.entries) >= self.limit:
                raise RuntimeError('audit_limit')
            paths = {tuple(item) if not isinstance(item, str) else (item,) for item in (withheld or ())}
            redacted = self._digest_value(args or {}, (), paths, [self.MAX_NODES])
            base = {
                'index': len(self.entries),
                'ts': self.clock.now(),
                'event': self._safe_text(event),
                'agent_id': self._safe_text(agent_id),
                'tool': tool if isinstance(tool, str) and tool in self.tool_names else (None if tool is None else '<withheld>'),
                'decision': self._safe_text(decision, 32),
                'reason': self._safe_text(reason),
                'args': redacted,
                'prev_hash': self.entries[-1].hash if self.entries else '0' * 64,
            }
            if len(json.dumps(base, sort_keys=True, separators=(',', ':')).encode()) > self.MAX_ENTRY_BYTES:
                base['args'] = {'<truncated>': self._digest(redacted)}
            if len(json.dumps(base, sort_keys=True, separators=(',', ':')).encode()) > self.MAX_ENTRY_BYTES:
                raise RuntimeError('audit_entry_too_large')
            entry = Entry(**base, hash=self._hash(base))
            prior_version = self._version
            self.entries.append(entry)
            self._version += 1
            if self._verify_cache_version == prior_version and self._verify_cache == (True, None):
                self._verify_cache_version = self._version
            else:
                self._verify_cache_version = -1
            return entry

    def verify(self):
        with self._lock:
            if self._verify_cache_version == self._version:
                return self._verify_cache
            version = self._version
            snapshot = list(self.entries)
        previous = '0' * 64
        result = (True, None)
        for position, entry in enumerate(snapshot):
            data = asdict(entry)
            stored = data.pop('hash')
            if entry.index != position or entry.prev_hash != previous or not hmac.compare_digest(self._hash(data), stored):
                result = (False, position)
                break
            previous = stored
        with self._lock:
            if self._version == version:
                self._verify_cache_version = version
                self._verify_cache = result
        return result

    def entry_count(self):
        with self._lock:
            return len(self.entries)

    def export_jsonl(self, offset=0, limit=None):
        """Export a bounded slice when limit is supplied; callers rendering UI must supply it."""
        if type(offset) is not int or offset < 0:
            raise ValueError('invalid_offset')
        if limit is not None and (type(limit) is not int or not 1 <= limit <= 200):
            raise ValueError('invalid_limit')

        def escape_digits(match):
            return re.sub(r'[0-9]', lambda digit: '\\u%04x' % ord(digit.group()), match.group())

        with self._lock:
            selected = self.entries[offset:] if limit is None else self.entries[offset:offset + limit]
            lines = [json.dumps(asdict(entry), sort_keys=True) for entry in selected]
        return '\n'.join(re.sub(r'"(?:[^"\\]|\\.)*"', escape_digits, line) for line in lines)


class DemoAuditLog(AuditLog):
    def __init__(self, *args, demo_tamper_enabled=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.demo_tamper_enabled = demo_tamper_enabled

    def _tamper_for_demo(self, index):
        if not self.demo_tamper_enabled:
            raise PermissionError('demo tampering disabled')
        with self._lock:
            if 0 <= index < len(self.entries):
                self.entries[index] = replace(self.entries[index], reason='tampered')
                self._version += 1
                self._verify_cache_version = -1
