import json

from .clock import FakeClock
from .policy import PolicyEngine
from .secrets_guard import BAD_KEY, lint_tool_definition, looks_like_secret
from .simulate import decode_json

MAX_TOOLS = 200
MAX_PROPERTIES = 64
MAX_AGENTS = 100
MAX_RULES = 200
MAX_POLICY_BYTES = 32768


def _safe_identifier(value):
    return isinstance(value, str) and not BAD_KEY.fullmatch(value) and not looks_like_secret(value, entropy=False)


def _clean_property(name, schema, warnings):
    if not _safe_identifier(name) or not name or len(name) > 64 or not isinstance(schema, dict):
        warnings.append('Dropped invalid property.')
        return None
    clean = {key: schema[key] for key in ('type', 'maximum', 'minimum', 'maxLength', 'enum') if key in schema}
    try:
        lint_tool_definition({name: clean})
    except ValueError:
        warnings.append(f'Dropped secret-like property {name}.')
        return None
    result = {'name': name, 'type': clean.get('type') if clean.get('type') in ('string', 'number', 'integer', 'boolean') else None}
    for source in ('maximum', 'minimum'):
        value = clean.get(source)
        if PolicyEngine._finite_number(value):
            result[source] = value
    length = clean.get('maxLength')
    if type(length) is int and length >= 0:
        result['maxLength'] = length
    enum = clean.get('enum')
    if isinstance(enum, list) and 0 < len(enum) <= 100 and not any(isinstance(value, (dict, list)) for value in enum):
        if not any(looks_like_secret(value) for value in enum):
            result['enum'] = enum
        else:
            warnings.append(f'Dropped secret-like enum for {name}.')
    return result


def import_catalogue(raw):
    warnings = []
    if isinstance(raw, str):
        if len(raw.encode()) > 1024 * 1024:
            raise ValueError('catalogue_too_large: maximum 1 MB')
        text = raw.strip()
        if not text:
            return [], warnings
        if text.startswith(('{', '[')):
            value = decode_json(text)
        else:
            value = []
            for line in text.splitlines():
                if line.strip():
                    if len(value) >= MAX_TOOLS:
                        raise ValueError('too_many_tools: maximum 200')
                    value.append({'name': line.strip()})
    else:
        value = raw
    if isinstance(value, dict):
        result = value.get('result', value)
        value = result.get('tools') if isinstance(result, dict) else None
    if not isinstance(value, list):
        raise ValueError('invalid_catalogue')
    if len(value) > MAX_TOOLS:
        raise ValueError('too_many_tools: maximum 200')
    tools, seen = [], set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            warnings.append(f'Dropped tool {index + 1}.')
            continue
        name = item.get('name')
        if not _safe_identifier(name) or not name or len(name) > 128 or name in seen:
            warnings.append(f'Dropped invalid, secret-like, or duplicate tool {index + 1}.')
            continue
        schema = item.get('inputSchema', {})
        properties = []
        schema_properties = schema.get('properties', {}) if isinstance(schema, dict) else {}
        if isinstance(schema_properties, dict):
            if len(schema_properties) > MAX_PROPERTIES:
                raise ValueError('too_many_properties: maximum 64 per tool')
            for property_name, definition in schema_properties.items():
                cleaned = _clean_property(property_name, definition, warnings)
                if cleaned:
                    properties.append(cleaned)
        description = item.get('description', '')
        if not isinstance(description, str):
            description = ''
        if looks_like_secret(description, entropy=False):
            warnings.append(f'Removed secret-like description from {name}.')
            description = ''
        tools.append({'name': name, 'description': description[:200], 'properties': properties})
        seen.add(name)
    return tools, warnings


def generate_policy(catalogue, agents, selected=None):
    if len(catalogue) > MAX_TOOLS:
        raise ValueError('too_many_tools: maximum 200; reimport a smaller catalogue')
    if len(agents) > MAX_AGENTS:
        raise ValueError('too_many_agents: maximum 100')
    agents = list(dict.fromkeys(agents))
    if any(not _safe_identifier(agent) or not 1 <= len(agent) <= 64 for agent in agents):
        raise ValueError('invalid_agent')
    tools = {tool['name']: tool for tool in catalogue}
    if selected is None:
        if len(agents) * len(tools) > MAX_RULES:
            raise ValueError('too_many_rules: explicitly select at most 200 pairs')
        pairs = [(agent, name) for agent in agents for name in tools]
    else:
        # An explicit empty selection means no permissions, never all pairs.
        pairs = []
        seen = set()
        for pair in selected:
            if len(pairs) >= MAX_RULES:
                raise ValueError('too_many_rules: maximum 200 selected pairs')
            pair = tuple(pair)
            if len(pair) != 2 or pair[0] not in agents or pair[1] not in tools:
                raise ValueError('invalid_selected_pair')
            if pair not in seen:
                seen.add(pair)
                pairs.append(pair)
        pairs.sort()
    rules, todos = [], []
    size = len(json.dumps({'version': 1, 'rules': []}).encode())
    for agent, name in pairs:
        tool = tools[name]
        if len(tool.get('properties', [])) > MAX_PROPERTIES:
            raise ValueError('too_many_properties')
        constraints = {}
        for prop in tool.get('properties', []):
            operations = {}
            for source, target in (('maximum', 'max'), ('minimum', 'min'), ('enum', 'in'), ('maxLength', 'max_len')):
                if source in prop:
                    operations[target] = prop[source]
            if prop.get('type') == 'string' and 'maxLength' not in prop:
                operations['max_len'] = 256
                todos.append(f'{name}.{prop["name"]}: confirm generated max_len 256.')
            if operations:
                constraints[prop['name']] = operations
        rule = {'agent': agent, 'tool': name, 'effect': 'allow', 'constraints': constraints}
        size += len(json.dumps(rule, allow_nan=False).encode()) + (2 if rules else 0)
        if size > MAX_POLICY_BYTES:
            raise ValueError('policy_too_large: select fewer pairs or properties')
        rules.append(rule)
    policy = {'version': 1, 'rules': rules}
    PolicyEngine(FakeClock(0), policy)
    return policy, todos
