from dataclasses import dataclass
import json
import math
import posixpath
import threading
from urllib.parse import unquote


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule_index: int | None = None


class PolicyEngine:
    OPS = {'max', 'min', 'in', 'prefix', 'max_len'}
    REASON_KEYS = {'amount', 'currency', 'order_id', 'account_id', 'path'}

    def __init__(self, clock, policy):
        self.clock = clock
        self._hits = {}
        self._lock = threading.RLock()
        self.load(policy)

    @staticmethod
    def _finite_number(value):
        try:
            return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)
        except (OverflowError, ValueError):
            return False

    def load(self, policy):
        try:
            raw = policy if isinstance(policy, str) else json.dumps(policy, allow_nan=False)
            if len(raw.encode()) > 32768:
                raise PolicyError('$: policy_too_large')
            obj = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
            raise PolicyError('$: invalid_json') from exc
        if not isinstance(obj, dict) or type(obj.get('version')) is not int or obj['version'] != 1 or not isinstance(obj.get('rules'), list):
            raise PolicyError('$: invalid_policy')
        if len(obj['rules']) > 200:
            raise PolicyError('$.rules: too_many_rules')
        for index, rule in enumerate(obj['rules']):
            path = f'$.rules[{index}]'
            if not isinstance(rule, dict):
                raise PolicyError(path + ': invalid_rule')
            if rule.get('effect') not in ('allow', 'deny') or not isinstance(rule.get('agent'), str) or not isinstance(rule.get('tool'), str):
                raise PolicyError(path + ': invalid_rule')
            if not 1 <= len(rule['agent']) <= 64 or not 1 <= len(rule['tool']) <= 128 or '*' in rule['tool']:
                raise PolicyError(path + ': invalid_selector')
            constraints = rule.get('constraints', {})
            if not isinstance(constraints, dict):
                raise PolicyError(path + '.constraints: invalid')
            rate = rule.get('rate_per_minute')
            if rate is not None and (type(rate) is not int or not 1 <= rate <= 10000):
                raise PolicyError(path + '.rate_per_minute: invalid')
            for key, operators in constraints.items():
                if not isinstance(key, str) or not 1 <= len(key) <= 64 or not isinstance(operators, dict) or not operators:
                    raise PolicyError(path + '.constraints: invalid')
                if set(operators) - self.OPS:
                    raise PolicyError(path + ': unknown_operator')
                for operator, expected in operators.items():
                    invalid = False
                    if operator in ('max', 'min'):
                        invalid = not self._finite_number(expected)
                    elif operator == 'max_len':
                        invalid = type(expected) is not int or expected < 0
                    elif operator == 'prefix':
                        invalid = not isinstance(expected, str) or not expected.startswith('/')
                    elif operator == 'in':
                        invalid = not isinstance(expected, list) or not expected or any(isinstance(item, (dict, list)) for item in expected)
                    if invalid:
                        raise PolicyError(path + ': invalid_operator_value')
        with self._lock:
            self.data = obj
            # Keep recent admissions across reloads; editing policy is not a
            # mechanism for resetting a tool's rate budget.

    def allowed_tools(self, agent):
        with self._lock:
            denied = {rule['tool'] for rule in self.data['rules'] if self._match(rule, agent) and rule['effect'] == 'deny'}
            return {rule['tool'] for rule in self.data['rules'] if self._match(rule, agent) and rule['effect'] == 'allow'} - denied

    @staticmethod
    def _match(rule, agent):
        return agent is not None and rule['agent'] in ('*', agent.name, agent.agent_id)

    @staticmethod
    def _safe_path(value, prefix):
        if not isinstance(value, str) or '\\' in value or '\x00' in value:
            return False
        decoded = value
        for _ in range(3):
            updated = unquote(decoded)
            if updated == decoded:
                break
            decoded = updated
        if '%' in decoded or any(part in ('..', '.') for part in decoded.split('/')):
            return False
        normalized = posixpath.normpath(decoded)
        base = posixpath.normpath(prefix)
        return normalized.startswith('/') and (normalized == base or normalized.startswith(base.rstrip('/') + '/'))

    def evaluate(self, agent, tool, args):
        """Atomically admit and reserve one call. Connector failures count too."""
        with self._lock:
            return self._evaluate(agent, tool, args)

    def _evaluate(self, agent, tool, args):
        if not isinstance(tool, str) or not isinstance(args, dict):
            return Decision(False, 'invalid_arguments')
        matches = [(index, rule) for index, rule in enumerate(self.data['rules']) if self._match(rule, agent) and rule['tool'] == tool]
        for index, rule in matches:
            if rule['effect'] == 'deny':
                return Decision(False, 'explicit_deny', index)
        fallback = 'no_matching_allow'
        fallback_index = matches[0][0] if matches else None
        for index, rule in matches:
            if rule['effect'] != 'allow':
                continue
            constraints = rule.get('constraints', {})
            failure = 'unexpected_arg' if set(args) - set(constraints) else self._constraints(constraints, args)
            if failure:
                fallback, fallback_index = failure, index
                continue
            limit = rule.get('rate_per_minute')
            if limit:
                now = self.clock.now()
                self._hits = {key: [stamp for stamp in hits if stamp > now - 60] for key, hits in self._hits.items() if any(stamp > now - 60 for stamp in hits)}
                key = (agent.agent_id, tool)
                recent = self._hits.setdefault(key, [])
                if len(recent) >= limit:
                    return Decision(False, 'rate_limited', index)
                recent.append(now)
            return Decision(True, 'allowed', index)
        return Decision(False, fallback, fallback_index)

    def record_success(self, agent, tool, decision):
        """Compatibility hook; evaluate already reserves the admission."""

    def _failure(self, key, operator):
        return f'constraint_failed:{key}.{operator}' if key in self.REASON_KEYS else 'constraint_failed'

    def _constraints(self, constraints, args):
        for key, operators in constraints.items():
            if key not in args:
                return self._failure(key, 'required')
            value = args[key]
            if isinstance(value, (dict, list, tuple, set)):
                return 'invalid_argument_type'
            for operator, expected in operators.items():
                if operator not in self.OPS:
                    return 'unknown_constraint'
                if operator in ('max', 'min'):
                    if not self._finite_number(value) or (operator == 'max' and value > expected) or (operator == 'min' and value < expected):
                        return self._failure(key, operator)
                elif operator == 'in':
                    if not any(type(value) is type(item) and value == item for item in expected):
                        return self._failure(key, operator)
                elif operator == 'prefix' and not self._safe_path(value, expected):
                    return self._failure(key, operator)
                elif operator == 'max_len' and (not isinstance(value, str) or len(value) > expected):
                    return self._failure(key, operator)
        return None
