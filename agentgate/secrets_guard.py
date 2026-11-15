import math
import re

PREFIX_RE = re.compile(r'(?i)(?:sk-(?:live_)?|AKIA|ASIA|gh[op]_|xox[abp]-|-----BEGIN|ags_)')
JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
BAD_KEY = re.compile(r'(?i)^(?:secret|password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|credential|private[_-]?key)$')


def looks_like_secret(value, entropy=True):
    if isinstance(value, bytes):
        value = value.decode('utf-8', 'ignore')
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if PREFIX_RE.search(candidate) or JWT_RE.search(candidate):
        return True
    if not entropy:
        return False
    compact = re.sub(r'\s+', '', candidate)
    if len(compact) < 20:
        return False
    counts = {char: compact.count(char) for char in set(compact)}
    score = -sum((count / len(compact)) * math.log2(count / len(compact)) for count in counts.values())
    return score >= 4.0


def secret_paths(value, path=()):
    found = set()
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = path + (str(key),)
            if BAD_KEY.search(str(key)) or looks_like_secret(str(key), entropy=False):
                found.add(child_path)
            found.update(secret_paths(child, child_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            found.update(secret_paths(child, path + (str(index),)))
    elif looks_like_secret(value):
        found.add(path)
    return found


def lint_tool_definition(definition):
    def visit(value, structural=False):
        if isinstance(value, dict):
            for key, child in value.items():
                if BAD_KEY.search(str(key)) or looks_like_secret(str(key), entropy=False):
                    raise ValueError('secret-like field in tool definition')
                visit(child, key in ('name', 'title', 'description'))
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, str) and looks_like_secret(value, entropy=not structural):
            raise ValueError('secret-like field in tool definition')
    visit(definition)
