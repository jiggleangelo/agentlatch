import json
import tempfile
import threading
import unittest
from pathlib import Path

from agentgate.sample_data import POLICY
from agentgate.secrets_guard import lint_tool_definition
from agentgate.simulate import run_suite
from agentgate.starter import import_catalogue
from agentgate.workspace import MissingWorkspace, WorkspaceStore


class WorkspaceRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = WorkspaceStore(self.temp.name)
        self.token = self.store.create({'policy': POLICY})

    def tearDown(self):
        self.temp.cleanup()

    def test_share_revoke_and_replacement_remove_markers(self):
        first = self.store.share(self.token)
        self.assertEqual(self.store.resolve_share(first)['policy']['current'], POLICY)
        second = self.store.share(self.token)
        with self.assertRaises(MissingWorkspace):
            self.store.resolve_share(first)
        self.store.revoke_share(self.token)
        with self.assertRaises(MissingWorkspace):
            self.store.resolve_share(second)
        self.assertIsNone(self.store.read(self.token)['meta']['share_hash'])

    def test_concurrent_updates_do_not_drop_cases(self):
        barrier = threading.Barrier(10)
        def add(number):
            barrier.wait()
            self.store.update(self.token, 'suite', lambda suite: {
                **suite, 'cases': suite['cases'] + [{'agent': str(number), 'tool': 'x', 'args': {}}]
            })
        threads = [threading.Thread(target=add, args=(number,)) for number in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(self.store.read(self.token)['suite']['cases']), 10)

    def test_sweep_removes_orphan_share_marker(self):
        share = self.store.share(self.token)
        marker = self.store.share_root / __import__('hashlib').sha256(share.encode()).hexdigest()
        directory = self.store.path(self.token)
        for path in directory.iterdir():
            if path.is_file():
                path.unlink()
        directory.rmdir()
        self.store.sweep()
        self.assertFalse(marker.exists())


class InputRegressionTests(unittest.TestCase):
    def test_realistic_mcp_schema_keeps_properties_and_long_names(self):
        raw = json.dumps({'result': {'tools': [{
            'name': 'github.create_pull_request_review_comment',
            'description': 'Create a review comment on a pull request in a repository.',
            'inputSchema': {'type': 'object', 'properties': {
                'max_tokens': {'type': 'integer', 'maximum': 4096, 'description': 'Maximum response tokens accepted by this operation.'},
                'body': {'type': 'string', 'maxLength': 5000, 'description': 'The review comment body to publish.'}
            }}
        }]}})
        tools, warnings = import_catalogue(raw)
        self.assertEqual([item['name'] for item in tools[0]['properties']], ['max_tokens', 'body'])
        self.assertFalse(any('Dropped secret-like property' in item for item in warnings))
        lint_tool_definition({'name': 'github.create_pull_request_review_comment'})

    def test_continuation_replays_rate_limit_history(self):
        policy = {'version': 1, 'rules': [{
            'agent': 'a', 'tool': 'x', 'effect': 'allow', 'constraints': {}, 'rate_per_minute': 2
        }]}
        cases = [{'agent': 'a', 'tool': 'x', 'args': {}, 't': value} for value in (0, 1, 2)]
        continued = run_suite(policy, cases, offset=2, deadline_seconds=60)
        self.assertEqual(continued['results'][0]['reason'], 'rate_limited')


if __name__ == '__main__':
    unittest.main()
