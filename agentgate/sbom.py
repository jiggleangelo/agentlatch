import hashlib
import json
from pathlib import Path


ROOT_FILES = ('demo.py', 'README.md', 'CRA_READINESS.md', 'RELEASE_GATE.md')


def generate(root=None):
    """Hash only project source/artifacts, never arbitrary deployment files."""
    root = Path(root or Path(__file__).resolve().parents[1]).resolve()
    components = [{'type': 'framework', 'name': 'python', 'version': '3.12'}]
    candidates = [root / name for name in ROOT_FILES]
    for directory, pattern in (('agentgate', '*.py'), ('tests', '*.py'), ('static', '*.css')):
        parent = root / directory
        if parent.is_dir() and not parent.is_symlink():
            candidates.extend(parent.glob(pattern))
    for path in sorted(set(candidates)):
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            continue
        components.append({
            'type': 'file', 'name': path.relative_to(root).as_posix(),
            'hashes': [{'alg': 'SHA-256', 'content': hashlib.sha256(path.read_bytes()).hexdigest()}],
        })
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1, 'components': components}


def main():
    print(json.dumps(generate(), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
