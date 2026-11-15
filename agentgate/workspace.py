import copy
import hashlib
import json
import os
import secrets
import shutil
import threading
import time
from collections import deque
from contextlib import contextmanager
from pathlib import Path

MAX_WORKSPACE_BYTES = 5 * 1024 * 1024
MAX_WORKSPACES = 3000


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


class StorageError(RuntimeError):
    pass


class MissingWorkspace(StorageError):
    pass


class WorkspaceStore:
    """One process, atomic workspace snapshots, and fixed, non-evicting locks.

    A transaction charges one write regardless of the number of updated fields.
    Readers and mutations of a workspace share the same lock. Run only one app
    process per DATA_DIR; these are thread locks, not interprocess locks.
    """

    def __init__(self, data_dir, cap_mb=200):
        self.root = Path(data_dir)
        self.ws_root = self.root / 'ws'
        self.share_root = self.root / 'share'
        self.tomb_root = self.root / 'tomb'
        for directory in (self.ws_root, self.share_root, self.tomb_root):
            directory.mkdir(parents=True, exist_ok=True)
        self.cap = int(cap_mb) * 1024 * 1024
        self._guard = threading.RLock()
        self._locks = tuple(threading.RLock() for _ in range(256))
        self._local = threading.local()
        self._new_hits = {}
        self._total_bytes = self._measure_total()

    def _measure_total(self):
        return sum(path.stat().st_size for path in self.root.rglob('*') if path.is_file())

    def lock(self, digest):
        return self._locks[int(digest[:8], 16) % len(self._locks)]

    def path(self, token):
        return self.ws_root / token_hash(token)

    def _atomic(self, path, value):
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        tmp = path.with_name('.' + path.name + '.' + secrets.token_hex(6) + '.tmp')
        try:
            with open(tmp, 'xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
            try:
                descriptor = os.open(path.parent, os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except OSError:
                pass
        finally:
            tmp.unlink(missing_ok=True)
        return len(raw)

    def _directory(self, digest):
        directory = self.ws_root / digest
        if not directory.is_dir() or (self.tomb_root / digest).exists():
            raise MissingWorkspace('Workspace not found.')
        return directory

    def _load(self, directory):
        snapshot = directory / 'state.json'
        if snapshot.exists():
            return json.loads(snapshot.read_text())
        # Read pre-upgrade workspaces; the next successful write migrates them.
        return {name: json.loads((directory / f'{name}.json').read_text())
                for name in ('meta', 'policy', 'tools', 'suite', 'log')}

    def _commit(self, directory, state, suite_run=False, rate_limit=True):
        now = time.time()
        meta = state['meta']
        if rate_limit:
            for key, limit, enabled in (('write_hits', 30, True), ('suite_hits', 10, suite_run)):
                hits = [stamp for stamp in meta.get(key, []) if stamp > now - 60]
                if enabled:
                    if len(hits) >= limit:
                        raise StorageError('Workspace write limit reached. Try again in a minute.')
                    hits.append(now)
                meta[key] = hits
            meta['last_write'] = now
        meta['last_seen'] = now
        raw = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > MAX_WORKSPACE_BYTES:
            raise StorageError('Workspace size limit reached; export and archive the log.')
        with self._guard:
            old = sum(path.stat().st_size for path in directory.iterdir() if path.is_file())
            if self._total_bytes - old + len(raw) > self.cap:
                raise StorageError('Storage is full; export your workspace.')
            size = self._atomic(directory / 'state.json', state)
            for name in ('meta', 'policy', 'tools', 'suite', 'log'):
                (directory / f'{name}.json').unlink(missing_ok=True)
            self._total_bytes += size - old

    @contextmanager
    def transaction(self, token):
        digest = token_hash(token)
        current = getattr(self._local, 'transaction', None)
        if current is not None:
            if current['digest'] != digest:
                raise RuntimeError('nested_workspace_transaction')
            yield
            return
        with self.lock(digest):
            directory = self._directory(digest)
            tx = {'digest': digest, 'state': self._load(directory), 'dirty': False,
                  'suite_run': False, 'deleted': False}
            self._local.transaction = tx
            try:
                yield
                if tx['dirty'] and not tx['deleted']:
                    self._directory(digest)
                    self._commit(directory, tx['state'], tx['suite_run'])
            finally:
                self._local.transaction = None

    def create(self, seed=None, source='local'):
        now = time.time()
        source = token_hash(str(source)[:128])
        with self._guard:
            self._new_hits = {key: deque(stamp for stamp in hits if stamp > now - 3600)
                              for key, hits in self._new_hits.items() if hits and hits[-1] > now - 3600}
            if source not in self._new_hits and len(self._new_hits) >= 4096:
                raise StorageError('Creation capacity reached; try again later.')
            hits = self._new_hits.setdefault(source, deque())
            if len(hits) >= 60:
                raise StorageError('Workspace creation limit reached for this client.')
            if sum(1 for item in self.ws_root.iterdir() if item.is_dir()) >= MAX_WORKSPACES:
                raise StorageError('Workspace capacity reached.')
            token = secrets.token_urlsafe(24)
            directory = self.path(token)
            policy = (seed or {}).get('policy', {'version': 1, 'rules': []})
            values = {
                'meta': {'created': now, 'last_seen': now, 'last_write': None, 'share_hash': None,
                         'write_hits': [], 'suite_hits': []},
                'policy': {'current': policy, 'versions': [policy], 'todos': []},
                'tools': (seed or {}).get('tools', []),
                'suite': {'cases': (seed or {}).get('cases', []), 'last_report': None},
                'log': {'entries': [], 'chain_key': secrets.token_hex(32), 'digest_key': secrets.token_hex(32)}
            }
            directory.mkdir(mode=0o700)
            try:
                self._commit(directory, values, rate_limit=False)
            except Exception:
                shutil.rmtree(directory)
                raise
            hits.append(now)
            return token

    def exists(self, token):
        digest = token_hash(token)
        return (self.ws_root / digest).is_dir() and not (self.tomb_root / digest).exists()

    def read(self, token):
        digest = token_hash(token)
        tx = getattr(self._local, 'transaction', None)
        if tx is not None and tx['digest'] == digest:
            if tx['deleted']:
                raise MissingWorkspace('Workspace not found.')
            return copy.deepcopy(tx['state'])
        with self.lock(digest):
            directory = self._directory(digest)
            state = self._load(directory)
            if state['meta'].get('last_seen', 0) < time.time() - 60:
                self._commit(directory, state, rate_limit=False)
            return state

    def read_file(self, token, name):
        return self.read(token)[name]

    def write(self, token, name, value, suite_run=False):
        if name not in ('policy', 'tools', 'suite', 'log'):
            raise ValueError('invalid_workspace_field')
        with self.transaction(token):
            tx = self._local.transaction
            tx['state'][name] = copy.deepcopy(value)
            tx['dirty'] = True
            tx['suite_run'] |= suite_run
        return value

    def update(self, token, name, mutator, suite_run=False):
        with self.transaction(token):
            value = self.read(token)[name]
            replacement = mutator(value)
            return self.write(token, name, value if replacement is None else replacement, suite_run)

    def share(self, token):
        with self.transaction(token):
            tx = self._local.transaction
            share = secrets.token_urlsafe(24)
            digest = token_hash(share)
            # Resolve always checks the committed meta value. An interrupted
            # transaction can leave only an unusable marker, removed by sweep.
            with self._guard:
                self._atomic(self.share_root / digest, token_hash(token))
                self._total_bytes = self._measure_total()
            tx['state']['meta']['share_hash'] = digest
            tx['dirty'] = True
            return share

    def revoke_share(self, token):
        with self.transaction(token):
            tx = self._local.transaction
            tx['state']['meta']['share_hash'] = None
            tx['dirty'] = True

    def resolve_share(self, share):
        marker = self.share_root / token_hash(share)
        try:
            digest = json.loads(marker.read_text())
        except (OSError, ValueError):
            raise MissingWorkspace('Review link not found.')
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in '0123456789abcdef' for char in digest):
            raise MissingWorkspace('Review link not found.')
        with self.lock(digest):
            state = self._load(self._directory(digest))
            if state['meta'].get('share_hash') != token_hash(share):
                marker.unlink(missing_ok=True)
                raise MissingWorkspace('Review link not found.')
            return state

    def delete(self, token):
        digest = token_hash(token)
        with self.lock(digest):
            directory = self._directory(digest)
            with self._guard:
                self._atomic(self.tomb_root / digest, {'deleted': time.time()})
                meta = self._load(directory)['meta']
                if meta.get('share_hash'):
                    (self.share_root / meta['share_hash']).unlink(missing_ok=True)
                shutil.rmtree(directory)
                self._total_bytes = self._measure_total()
            tx = getattr(self._local, 'transaction', None)
            if tx is not None and tx['digest'] == digest:
                tx['deleted'] = True

    def sweep(self, now=None):
        now = time.time() if now is None else now
        for directory in list(self.ws_root.iterdir()):
            if not directory.is_dir():
                continue
            try:
                with self.lock(directory.name):
                    meta = self._load(directory)['meta']
                    remove = ((meta.get('last_write') is None and meta.get('created', now) < now - 86400)
                              or meta.get('last_seen', meta.get('created', now)) < now - 90 * 86400)
                    if remove:
                        with self._guard:
                            self._atomic(self.tomb_root / directory.name, {'deleted': now})
                            shutil.rmtree(directory)
                            self._total_bytes = self._measure_total()
            except (OSError, ValueError, KeyError):
                continue
        for marker in list(self.share_root.iterdir()):
            try:
                digest = json.loads(marker.read_text())
                if not isinstance(digest, str) or len(digest) != 64:
                    raise ValueError('invalid_marker')
                with self.lock(digest):
                    state = self._load(self._directory(digest))
                    if state['meta'].get('share_hash') != marker.name:
                        marker.unlink(missing_ok=True)
            except (OSError, ValueError, KeyError, MissingWorkspace):
                marker.unlink(missing_ok=True)
        with self._guard:
            for marker in list(self.tomb_root.iterdir()):
                if marker.stat().st_mtime < now - 7 * 86400:
                    marker.unlink(missing_ok=True)
            self._total_bytes = self._measure_total()
