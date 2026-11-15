import json


def lint_policy(policy, catalogue=(), cases=(), last_report=None, todos=()):
    rules = policy.get('rules', []) if isinstance(policy, dict) else []
    tool_names = {item['name'] for item in catalogue}
    ruled_tools = {rule.get('tool') for rule in rules}
    denied = {(rule.get('agent'), rule.get('tool')) for rule in rules if rule.get('effect') == 'deny'}
    findings = []

    def add(code, message, rule=None, level='warning'):
        item = {'id': code, 'level': level, 'message': message}
        if rule is not None:
            item['rule'] = rule
        findings.append(item)

    seen = {}
    for index, rule in enumerate(rules):
        if rule.get('effect') == 'allow':
            if rule.get('agent') == '*':
                add('L1', 'Wildcard allow applies to every agent.', index)
            if not rule.get('constraints'):
                add('L2', 'Allow has no constraints; it permits only calls with no arguments.', index)
            if (rule.get('agent'), rule.get('tool')) in denied or ('*', rule.get('tool')) in denied:
                add('L3', 'Allow is fully shadowed by a matching deny.', index)
        if tool_names and rule.get('tool') not in tool_names:
            add('L4', 'Rule references a tool missing from the catalogue.', index)
        for key, operators in rule.get('constraints', {}).items():
            if ('min' in operators or isinstance(operators.get('in'), list) and any(isinstance(x, (int, float)) and not isinstance(x, bool) for x in operators['in'])) and 'max' not in operators:
                add('L6', f'Numeric argument {key} has no maximum.', index)
            if any(word in key.lower() for word in ('path', 'file', 'directory', 'folder')) and 'prefix' not in operators:
                add('L7', f'Path-like argument {key} has no prefix.', index)
        signature = json.dumps(rule, sort_keys=True, separators=(',', ':'))
        if signature in seen:
            add('L9', f'Duplicate of rule {seen[signature]}.', index)
        else:
            seen[signature] = index
    for name in sorted(tool_names - ruled_tools):
        add('L5', f'{name} has no rule and is denied by default.', level='info')
    exercised = {result.get('rule_index') for result in (last_report or {}).get('results', []) if result.get('rule_index') is not None}
    if last_report is not None:
        for index in range(len(rules)):
            if index not in exercised:
                add('L8', 'No test in the last run exercised this rule.', index, 'info')
    for item in todos:
        add('TODO', item, level='info')
    return findings
