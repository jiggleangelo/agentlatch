from dataclasses import dataclass
import json
import threading
from .identity import AuthError
from .secrets_guard import secret_paths
from .tokens import TokenError


class UnauthenticatedAuditLimit(Exception):
    """Retained for API compatibility; unauthenticated denials are no longer silently dropped."""


@dataclass
class CallResult:
    allowed: bool
    reason: str
    result: dict | None = None
    error: str | None = None


class Gateway:
    MAX_ARGUMENT_KEYS = 16
    MAX_ARGUMENT_KEY_BYTES = 64
    MAX_ARGUMENT_VALUE_BYTES = 1024
    MAX_ARGUMENTS_BYTES = 4096

    def __init__(self, registry, tokens, policy, audit, connector, metering=None, unauthenticated_audit_limit=20):
        self.registry = registry
        self.tokens = tokens
        self.policy = policy
        self.audit = audit
        self.connector = connector
        self.metering = metering
        self.unauthenticated_audit_limit = unauthenticated_audit_limit
        self._lock = threading.RLock()
        self.audit.tool_names = frozenset(tool['name'] for tool in connector.list_tools())

    @classmethod
    def arguments_valid(cls, args):
        if not isinstance(args, dict) or len(args) > cls.MAX_ARGUMENT_KEYS:
            return False
        total = 2
        for key, value in args.items():
            if not isinstance(key, str) or not key or len(key.encode()) > cls.MAX_ARGUMENT_KEY_BYTES:
                return False
            try:
                encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
            except (TypeError, ValueError, UnicodeError, RecursionError):
                return False
            if len(encoded) > cls.MAX_ARGUMENT_VALUE_BYTES:
                return False
            total += len(key.encode()) + len(encoded) + 4
            if total > cls.MAX_ARGUMENTS_BYTES:
                return False
        return True

    def _audit_unauthenticated(self, event, tool=None):
        self.audit.append(event, 'unauthenticated', tool, 'deny',
                          'invalid_client' if event == 'token.issue' else 'invalid_token', {})

    def issue_token(self, client_id, secret, scopes, ttl=300, source='local'):
        with self._lock:
            try:
                agent = self.registry.authenticate(client_id, secret, source)
            except AuthError:
                self._audit_unauthenticated('token.issue')
                raise
            try:
                token, claims = self.tokens.exchange(agent, scopes, self.policy.allowed_tools(agent), ttl)
            except TokenError:
                self.audit.append('token.issue', agent.agent_id, decision='deny', reason='invalid_scope')
                raise
            self.audit.append('token.issue', agent.agent_id, decision='allow', reason='issued')
            if self.metering:
                self.metering.record(agent.agent_id)
            return token, claims

    def call(self, token, tool, args):
        with self._lock, self.audit._lock:
            if len(self.audit.entries) >= self.audit.limit:
                return CallResult(False, 'audit_failure')
            return self._call(token, tool, args)

    def _call(self, token, tool, args):
        try:
            claims = self.tokens.verify(token)
        except TokenError:
            try:
                self._audit_unauthenticated('tool.call', tool)
            except Exception:
                return CallResult(False, 'audit_failure')
            return CallResult(False, 'invalid_token')
        agent_id = claims['sub']
        if not self.arguments_valid(args):
            return self._deny(agent_id, tool, {}, 'invalid_arguments')
        try:
            withheld = secret_paths(args)
        except (RecursionError, ValueError):
            return self._deny(agent_id, tool, {}, 'invalid_arguments')
        if not isinstance(tool, str) or tool not in claims['scp']:
            return self._deny(agent_id, tool, args, 'out_of_scope', withheld)
        if withheld:
            return self._deny(agent_id, tool, args, 'secret_in_args', withheld)
        if any(isinstance(value, (dict, list, tuple, set)) for value in args.values()):
            return self._deny(agent_id, tool, args, 'invalid_argument_type', withheld)
        agent = self.registry.get(agent_id)
        decision = self.policy.evaluate(agent, tool, args)
        if not decision.allowed:
            return self._deny(agent_id, tool, args, decision.reason, withheld)
        try:
            self.audit.append('tool.call', agent_id, tool, 'allow', 'allowed', args, withheld)
        except Exception:
            return CallResult(False, 'audit_failure')
        try:
            assertion, _ = self.tokens.issue_connector_assertion(agent, tool, args, 30)
            result = self.connector.invoke(tool, args, assertion)
        except Exception:
            return CallResult(True, 'connector_error', None, 'connector_error')
        return CallResult(True, 'allowed', result)

    def _deny(self, agent_id, tool, args, reason, withheld=()):
        try:
            self.audit.append('tool.call', agent_id, tool, 'deny', reason, args, withheld)
        except Exception:
            return CallResult(False, 'audit_failure')
        return CallResult(False, reason)

    def mcp(self, request, bearer):
        request = request if isinstance(request, dict) else {}
        request_id = request.get('id')
        if not isinstance(request_id, (str, int, type(None))) or isinstance(request_id, bool):
            request_id = None

        def error(code, message):
            return {'jsonrpc': '2.0', 'id': request_id, 'error': {'code': code, 'message': message}}

        if request.get('jsonrpc') != '2.0' or not isinstance(request.get('method'), str):
            return error(-32600, 'Invalid Request')
        try:
            claims = self.tokens.verify(bearer)
        except TokenError:
            try:
                self._audit_unauthenticated('tool.call')
            except Exception:
                return error(-32002, 'Audit unavailable')
            return error(-32001, 'Unauthorised')
        method = request['method']
        if method == 'tools/list':
            tools = [item for item in self.connector.list_tools() if item['name'] in claims['scp']]
            return {'jsonrpc': '2.0', 'id': request_id, 'result': {'tools': tools}}
        if method == 'tools/call':
            params = request.get('params')
            if not isinstance(params, dict) or not isinstance(params.get('name'), str) or not isinstance(params.get('arguments', {}), dict):
                return error(-32602, 'Invalid params')
            result = self.call(bearer, params['name'], params.get('arguments', {}))
            return {'jsonrpc': '2.0', 'id': request_id, 'result': {'allowed': result.allowed, 'reason': result.reason, 'content': result.result}}
        return error(-32601, 'Method not found')
