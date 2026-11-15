import hashlib
import json
import math
import time
from dataclasses import asdict, dataclass

from .clock import FakeClock
from .gateway import Gateway
from .identity import Agent
from .policy import PolicyEngine as BasePolicyEngine
from .secrets_guard import secret_paths


class PolicyEngine(BasePolicyEngine):
    """Hosted checker reason detail; the original gateway engine is unchanged."""

    def _failure(self, key, operator):
        return f'constraint_failed:{key}.{operator}'


@dataclass(frozen=True)
class CaseResult:
    case: int
    agent: str
    tool: str
    allowed: bool
    decision: str
    reason: str
    rule_index: int | None
    expect: str | None
    passed: bool | None
    warning: str | None = None


def decode_json(raw):
    value = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('invalid_json')))
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 32:
            raise ValueError('invalid_json')
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def parse_arguments(raw):
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raise ValueError('Arguments must be a JSON object or key=value lines.')
    text = raw.strip()
    if not text:
        return {}
    if text.startswith(('{', '[')):
        result = decode_json(text)
        if not isinstance(result, dict):
            raise ValueError('Arguments must be a JSON object.')
        return result
    result = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        key, separator, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if not separator or not key:
            raise ValueError(f'Arguments line {number}: expected key=value.')
        try:
            result[key] = decode_json(value)
        except ValueError:
            result[key] = value
    return result


def parse_jsonl(raw, limit=500):
    cases, errors = [], []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        if len(cases) >= min(limit, 500):
            errors.append({'line': number, 'error': 'too_many_cases'})
            break
        try:
            case = decode_json(line)
            if not isinstance(case, dict) or not isinstance(case.get('agent'), str) or not isinstance(case.get('tool'), str) or not isinstance(case.get('args', {}), dict):
                raise ValueError('invalid_case')
            if not 1 <= len(case['agent']) <= 64 or not 1 <= len(case['tool']) <= 128:
                raise ValueError('invalid_selector')
            expect = case.get('expect')
            if expect is not None and (not isinstance(expect, str) or len(expect) > 256):
                raise ValueError('invalid_expect')
            t = case.get('t', 0)
            if isinstance(t, bool) or not isinstance(t, (int, float)) or not math.isfinite(t) or t < 0:
                raise ValueError('invalid_t')
            cases.append({'agent': case['agent'], 'tool': case['tool'], 'args': case.get('args', {}), 'expect': expect, 't': t})
        except (ValueError, TypeError, OverflowError, RecursionError) as exc:
            errors.append({'line': number, 'error': str(exc) or 'invalid_case'})
    return cases, errors


def run_case(engine, case, clock, catalogue=()):
    agent_name = case.get('agent', '')
    tool = case.get('tool', '')
    args = case.get('args', {})
    names = catalogue if isinstance(catalogue, (set, frozenset)) else {item['name'] for item in catalogue}
    warning = None if not names or tool in names else 'tool_missing_from_catalogue'
    agent = Agent(agent_id=agent_name, name=agent_name, secret_hash=b'', salt=b'', created_at=0)
    if not Gateway.arguments_valid(args):
        allowed, reason, rule_index = False, 'invalid_arguments', None
    else:
        try:
            secrets = secret_paths(args)
        except (ValueError, RecursionError):
            allowed, reason, rule_index = False, 'invalid_arguments', None
        else:
            if secrets:
                allowed, reason, rule_index = False, 'secret_in_args', None
            elif any(isinstance(value, (dict, list, tuple, set)) for value in args.values()):
                allowed, reason, rule_index = False, 'invalid_argument_type', None
            else:
                decision = engine.evaluate(agent, tool, args)
                allowed, reason, rule_index = decision.allowed, decision.reason, decision.rule_index
    outcome = 'allow' if allowed else 'deny'
    expect = case.get('expect')
    passed = None if expect is None else expect in (outcome, reason)
    return CaseResult(0, agent_name, tool, allowed, outcome, reason, rule_index, expect, passed, warning)


def run_suite(policy, cases, catalogue=(), offset=0, deadline_seconds=2.0, checkpoint=None):
    started = time.monotonic()
    if type(offset) is not int or not 0 <= offset <= len(cases):
        raise ValueError('invalid_offset')
    if len(cases) > 500:
        raise ValueError('too_many_cases')
    fingerprint = hashlib.sha256(json.dumps([policy, cases, catalogue], sort_keys=True, allow_nan=False).encode()).hexdigest()
    clock = FakeClock(0)
    engine = PolicyEngine(clock, policy)
    indexed = sorted(enumerate(cases), key=lambda pair: (pair[1].get('t', 0), pair[0]))
    cursor = 0
    if checkpoint is not None:
        if checkpoint.get('fingerprint') != fingerprint or checkpoint.get('next_offset') != offset:
            raise ValueError('Suite or policy changed; start a new run.')
        cursor = checkpoint['cursor']
        if type(cursor) is not int or not 0 <= cursor <= offset:
            raise ValueError('invalid_checkpoint')
        clock.value = checkpoint['clock']
        engine._hits = {(agent, tool): stamps for agent, tool, stamps in checkpoint['hits']}
    names = frozenset(item['name'] for item in catalogue)
    results = []
    while cursor < len(indexed):
        # Includes compatibility replay when a caller supplies only an offset.
        if time.monotonic() - started >= deadline_seconds:
            break
        original_index, case = indexed[cursor]
        clock.value = max(clock.now(), case.get('t', 0))
        result = asdict(run_case(engine, case, clock, names))
        result['case'] = original_index + 1
        if cursor >= offset:
            results.append(result)
        cursor += 1
    complete = cursor == len(indexed)
    next_offset = None if complete else max(offset, cursor)
    saved = None if complete else {
        'fingerprint': fingerprint, 'cursor': cursor, 'next_offset': next_offset,
        'clock': clock.now(), 'hits': [[agent, tool, stamps] for (agent, tool), stamps in engine._hits.items()]
    }
    return {'results': results, 'complete': complete, 'next_offset': next_offset,
            'checkpoint': saved,
            'passed': sum(item['passed'] is True for item in results),
            'failed': sum(item['passed'] is False for item in results)}


def outcome_diff(old_policy, new_policy, cases, catalogue=()):
    old = run_suite(old_policy, cases, catalogue)
    new = run_suite(new_policy, cases, catalogue)
    if not old['complete'] or not new['complete']:
        raise ValueError('Policy comparison exceeded its deadline; use a smaller suite.')
    return [{'case': left['case'], 'old': {'decision': left['decision'], 'reason': left['reason']},
             'new': {'decision': right['decision'], 'reason': right['reason']}}
            for left, right in zip(old['results'], new['results'])
            if (left['decision'], left['reason']) != (right['decision'], right['reason'])]
