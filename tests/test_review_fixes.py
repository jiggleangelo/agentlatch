import copy
import http.client
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

import app
from agentgate.clock import FakeClock
from agentgate.lint import lint_policy
from agentgate.simulate import PolicyEngine, run_case, run_suite
from agentgate.starter import generate_policy, import_catalogue
from agentgate.workspace import StorageError, WorkspaceStore


class ReviewUnitTests(unittest.TestCase):
    def test_catalogue_count_cap_for_all_formats(self):
        tools = [{'name': f'tool{i}'} for i in range(201)]
        for raw in ('\n'.join(item['name'] for item in tools), json.dumps(tools), json.dumps({'result': {'tools': tools}})):
            with self.subTest(raw=raw[:30]):
                with self.assertRaisesRegex(ValueError, 'too_many_tools'):
                    import_catalogue(raw)
        self.assertEqual(len(import_catalogue('\n'.join(f'tool{i}' for i in range(200)))[0]), 200)

    def test_generation_rejects_product_before_building_rules(self):
        tools = [{'name': f'tool{i}', 'properties': []} for i in range(200)]
        with self.assertRaisesRegex(ValueError, 'too_many_rules'):
            generate_policy(tools, ['a', 'b'])
        self.assertEqual(generate_policy(tools, ['a', 'b'], set())[0]['rules'], [])
        policy, _ = generate_policy(tools, ['a', 'b'], [('b', 'tool199')])
        self.assertEqual(len(policy['rules']), 1)
        self.assertEqual(policy['rules'][0]['agent'], 'b')

    def test_generation_enforces_byte_limit(self):
        tools = [{'name': 'x', 'properties': [{'name': f'p{i}', 'type': 'string', 'enum': ['v' * 200]} for i in range(64)]}]
        with self.assertRaisesRegex(ValueError, 'policy_too_large'):
            generate_policy(tools, ['a', 'b', 'c'])

    def test_lint_tool_lookup_is_linear_in_rules(self):
        class CountedRule(dict):
            reads = 0
            def get(self, *args):
                type(self).reads += 1
                return super().get(*args)
        rules = [CountedRule(agent='a', tool=f't{i}', effect='deny') for i in range(200)]
        findings = lint_policy({'rules': rules}, [{'name': f't{i}'} for i in range(2000)])
        self.assertEqual(sum(item['id'] == 'L5' for item in findings), 1800)
        self.assertLess(CountedRule.reads, 5000)

    def test_arbitrary_constraint_names_have_exact_reasons(self):
        for key, operators, args, suffix in (
            ('limit', {'max': 4}, {'limit': 5}, 'max'),
            ('repo', {'in': ['safe']}, {'repo': 'other'}, 'in'),
            ('custom', {'max_len': 3}, {}, 'required'),
        ):
            policy = {'version': 1, 'rules': [{'agent': 'a', 'tool': 'x', 'effect': 'allow', 'constraints': {key: operators}}]}
            report = run_suite(policy, [{'agent': 'a', 'tool': 'x', 'args': args, 'expect': f'constraint_failed:{key}.{suffix}'}])
            self.assertEqual(report['passed'], 1)

    def test_withholding_uses_secret_paths_in_nested_values(self):
        value = {'password': 'Summer2024!', 'api_key': 'short', 'nested': [{'credential': 'shorter'}], 'limit': 3}
        clean = app.withheld_copy(value)
        self.assertEqual(clean['password'], '<withheld>')
        self.assertEqual(clean['api_key'], '<withheld>')
        self.assertEqual(clean['nested'][0]['credential'], '<withheld>')
        self.assertEqual(clean['limit'], 3)
        self.assertNotIn('Summer2024!', json.dumps(clean))

    def test_structural_names_and_english_descriptions_survive(self):
        name = 'github.create_pull_request_review_comment'
        description = 'Create a review comment on a pull request in a repository.'
        tools, warnings = import_catalogue(json.dumps([{'name': name, 'description': description}]))
        self.assertEqual(tools[0]['description'], description)
        self.assertEqual(warnings, [])
        policy = {'version': 1, 'rules': [{'agent': 'pull-request-review-comment-agent', 'tool': name, 'effect': 'allow', 'constraints': {}}]}
        self.assertFalse(app.has_secret(policy))
        policy['rules'][0]['constraints'] = {'value': {'in': ['sk-live_example_secret']}}
        self.assertTrue(app.has_secret(policy))

    def test_replay_deadline_and_checkpoint(self):
        policy = {'version': 1, 'rules': [{'agent': 'a', 'tool': 'x', 'effect': 'allow', 'constraints': {}, 'rate_per_minute': 2}]}
        cases = [{'agent': 'a', 'tool': 'x', 'args': {}, 't': i} for i in range(5)]
        with patch('agentgate.simulate.time.monotonic', side_effect=[0, 0, 3]):
            partial = run_suite(policy, cases, offset=3, deadline_seconds=2)
        self.assertEqual(partial['results'], [])
        self.assertFalse(partial['complete'])
        self.assertEqual(partial['checkpoint']['cursor'], 1)
        with patch('agentgate.simulate.run_case', wraps=run_case) as evaluated:
            report = run_suite(policy, cases, offset=partial['next_offset'], checkpoint=partial['checkpoint'], deadline_seconds=60)
        self.assertEqual(evaluated.call_count, 4)
        self.assertEqual(report['results'][0]['reason'], 'rate_limited')
        with self.assertRaisesRegex(ValueError, 'changed'):
            run_suite(policy, cases[:-1], offset=3, checkpoint=partial['checkpoint'])

    def test_lock_identity_never_changes_after_churn(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(directory)
            digest = '0' * 64
            original = store.lock(digest)
            with original:
                for number in range(5000):
                    store.lock(f'{number:064x}')
                self.assertIs(store.lock(digest), original)
            self.assertEqual(len(store._locks), 256)

    def test_atomic_transaction_rolls_back_all_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(directory)
            token = store.create()
            before = store.read(token)
            with self.assertRaises(StorageError):
                with store.transaction(token):
                    store.write(token, 'suite', {'cases': [{'agent': 'a'}], 'last_report': None})
                    raise StorageError('audit full')
            self.assertEqual(store.read(token), before)

    def test_creation_limits_are_per_source(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(directory)
            for _ in range(60):
                store.create(source='192.0.2.1')
            with self.assertRaises(StorageError):
                store.create(source='192.0.2.1')
            self.assertTrue(store.exists(store.create(source='192.0.2.2')))

    def test_public_configuration_required_and_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'PUBLIC_BASE_URL'):
                app.make_server(('0.0.0.0', 0), directory)
            for value in ('http://example.com', 'https://user@example.com', 'https://example.com/path'):
                with self.assertRaises(ValueError):
                    app.public_origin(value)
        with patch.dict('os.environ', {'APP_HOST': '0.0.0.0', 'APP_HTTPS_TERMINATED': 'true', 'PUBLIC_BASE_URL': ''}, clear=True):
            with self.assertRaisesRegex(ValueError, 'PUBLIC_BASE_URL'):
                app.main()

    def test_proxy_configuration_disables_uri_logging(self):
        root = Path(__file__).resolve().parents[1]
        config = (root / 'deploy' / 'nginx.conf').read_text()
        self.assertIn('access_log off;', config)
        self.assertIn('error_log /dev/null;', config)
        self.assertNotIn('$request_uri', config)
        self.assertIn('proxy_bind $remote_addr transparent;', config)
        self.assertIn('load balancer', (root / 'README.md').read_text())


class ReviewHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.origin = 'https://app-agentlatch.manykiln.com'
        self.server = app.make_server(('127.0.0.1', 0), self.temp.name, self.origin)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.temp.cleanup()

    def request(self, method, path, values=None, headers=None):
        supplied = {'Host': 'app-agentlatch.manykiln.com', **(headers or {})}
        body = None
        if values is not None:
            body = urlencode(values)
            supplied.setdefault('Content-Type', 'application/x-www-form-urlencoded')
            supplied.setdefault('Origin', self.origin)
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        try:
            connection.request(method, path, body, supplied)
            response = connection.getresponse()
            return response.status, response.read().decode(), dict(response.getheaders())
        finally:
            connection.close()

    def workspace(self, sample=False):
        status, _, headers = self.request('POST', '/new', {'sample': '1' if sample else '0'})
        self.assertEqual(status, 303)
        return headers['Location'][3:]

    def test_http_creation_passes_peer_not_forwarded_header(self):
        with patch.object(self.server.store, 'create', wraps=self.server.store.create) as create:
            self.request('POST', '/new', {'sample': '0'}, {'X-Forwarded-For': '198.51.100.7'})
        self.assertEqual(create.call_args.kwargs['source'], '127.0.0.1')

    def test_tools_page_does_not_expand_cartesian_product(self):
        token = self.workspace()
        tools = [{'name': f'tool{i}', 'description': '', 'properties': []} for i in range(200)]
        self.server.store.write(token, 'tools', tools)
        rules = [{'agent': f'a{i}', 'tool': 'tool0', 'effect': 'deny'} for i in range(200)]
        self.server.store.write(token, 'policy', {'current': {'version': 1, 'rules': rules}, 'versions': [], 'todos': []})
        status, page, _ = self.request('GET', f'/w/{token}/tools')
        self.assertEqual(status, 200)
        self.assertLess(len(page), 100000)
        self.assertNotIn('a199|tool199', page)
        self.assertIn('name=selected rows=10></textarea>', page)

    def test_five_hundred_failures_produce_report_and_one_write_charge(self):
        token = self.workspace()
        raw = '\n'.join(json.dumps({'agent': 'a', 'tool': 'x', 'args': {}, 'expect': 'allow', 't': i}) for i in range(500))
        status, page, _ = self.request('POST', f'/w/{token}/suite', {'jsonl': raw})
        self.assertEqual(status, 200)
        self.assertIn('500 failed', page)
        state = self.server.store.read(token)
        self.assertEqual(len(state['log']['entries']), 500)
        self.assertEqual(len(state['meta']['write_hits']), 1)
        self.assertEqual(app.audit_from(state['log']).verify(), (True, None))

    def test_full_log_refuses_atomically_and_archive_restores_checks(self):
        token = self.workspace(True)
        state = self.server.store.read(token)
        log = app.audit_from(state['log'], state['tools'])
        for _ in range(app.AUDIT_LIMIT):
            log.append('call.check', 'a', reason='no_matching_allow')
        state['log']['entries'] = [asdict(item) for item in log.entries]
        self.server.store.write(token, 'log', state['log'])
        before = self.server.store.read(token)
        status, page, _ = self.request('POST', f'/w/{token}/policy', {'policy': '{"version":1,"rules":[]}'})
        self.assertEqual(status, 429)
        self.assertIn('No changes were saved', page)
        after = self.server.store.read(token)
        for name in ('policy', 'suite', 'log'):
            self.assertEqual(after[name], before[name])
        status, exported, _ = self.request('POST', f'/w/{token}/log/archive', {})
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(exported)['entries']), app.AUDIT_LIMIT)
        self.assertEqual(self.request('POST', f'/w/{token}/check', {'agent': 'a', 'tool': 'x', 'arguments': '{}'})[0], 200)
        self.assertEqual(app.audit_from(self.server.store.read(token)['log']).verify(), (True, None))

    def test_empty_run_preserves_saved_suite(self):
        token = self.workspace()
        self.request('POST', f'/w/{token}/check', {'agent': 'a', 'tool': 'x', 'arguments': '{}', 'save': '1'})
        status, _, _ = self.request('POST', f'/w/{token}/suite', {'jsonl': ''})
        self.assertEqual(status, 200)
        self.assertEqual(len(self.server.store.read(token)['suite']['cases']), 1)
        self.request('POST', f'/w/{token}/suite', {'mode': 'replace', 'jsonl': ''})
        self.assertEqual(self.server.store.read(token)['suite']['cases'], [])

    def test_validation_preserves_forms_and_paths(self):
        token = self.workspace()
        policy = {'version': 1, 'rules': [{'agent': 'a', 'tool': 'x', 'effect': 'allow', 'constraints': {'limit': {'max': 'wrong'}}}]}
        status, page, _ = self.request('POST', f'/w/{token}/policy', {'policy': json.dumps(policy)})
        self.assertEqual(status, 400)
        self.assertIn('$.rules[0]: invalid_operator_value', page)
        self.assertIn('name=policy', page)
        self.assertIn('wrong', page)
        status, page, _ = self.request('POST', f'/w/{token}/check', {'agent': 'a', 'tool': 'x', 'arguments': 'missing equals'})
        self.assertEqual(status, 400)
        self.assertIn('Arguments line 1', page)
        self.assertIn('missing equals</textarea>', page)

    def test_secret_named_values_never_reach_storage(self):
        token = self.workspace()
        raw = json.dumps({'agent': 'a', 'tool': 'x', 'args': {'password': 'Summer2024!', 'api_key': 'short'}})
        self.assertEqual(self.request('POST', f'/w/{token}/suite', {'jsonl': raw})[0], 200)
        self.request('POST', f'/w/{token}/check', {'agent': 'a', 'tool': 'x', 'arguments': '{"password":"Different2024!"}', 'save': '1'})
        disk = ''.join(path.read_text() for path in Path(self.temp.name).rglob('*') if path.is_file())
        self.assertNotIn('Summer2024!', disk)
        self.assertNotIn('Different2024!', disk)
        self.assertNotIn('"api_key":"short"', disk)

    def test_concurrent_http_saves_preserve_cases_and_log(self):
        token = self.workspace()
        barrier = threading.Barrier(8)
        def save(index):
            barrier.wait()
            return self.request('POST', f'/w/{token}/check', {'agent': f'a{index}', 'tool': 'x', 'arguments': '{}', 'save': '1'})[0]
        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(save, range(8)))
        self.assertEqual(statuses, [200] * 8)
        state = self.server.store.read(token)
        self.assertEqual(len(state['suite']['cases']), 8)
        self.assertEqual(len(state['log']['entries']), 8)
        self.assertEqual(app.audit_from(state['log']).verify(), (True, None))

    def test_continuation_logs_only_new_cases(self):
        token = self.workspace()
        raw = '\n'.join(json.dumps({'agent': 'a', 'tool': 'x', 'args': {}, 'expect': 'allow'}) for _ in range(4))
        original = app.run_suite
        def partial(*args, **kwargs):
            with patch('agentgate.simulate.time.monotonic', side_effect=[0, 0, 0, 3]):
                return original(*args, **kwargs)
        with patch('app.run_suite', side_effect=partial):
            self.assertEqual(self.request('POST', f'/w/{token}/suite', {'jsonl': raw})[0], 200)
        state = self.server.store.read(token)
        self.assertEqual(len(state['log']['entries']), 2)
        offset = state['suite']['last_report']['next_offset']
        self.assertEqual(self.request('POST', f'/w/{token}/suite', {'offset': str(offset)})[0], 200)
        state = self.server.store.read(token)
        self.assertEqual(len(state['log']['entries']), 4)
        self.assertEqual(state['suite']['last_report']['failed'], 4)
        self.assertEqual(self.request('POST', f'/w/{token}/suite', {'offset': str(offset)})[0], 400)
        self.assertEqual(len(self.server.store.read(token)['log']['entries']), 4)

    def test_noindex_pagination_and_policy_restore(self):
        token = self.workspace(True)
        share = self.server.store.share(token)
        status, page, headers = self.request('GET', '/s/' + share)
        self.assertEqual(status, 200)
        self.assertIn('name=robots content=noindex', page)
        self.assertIn('noindex', headers['X-Robots-Tag'])
        self.assertNotIn('<form', page)
        state = self.server.store.read(token)
        log = app.audit_from(state['log'])
        for _ in range(51):
            log.append('event', 'a')
        state['log']['entries'] = [asdict(item) for item in log.entries]
        self.server.store.write(token, 'log', state['log'])
        self.assertIn('>Next</a>', self.request('GET', f'/w/{token}/log')[1])
        self.assertIn('>Previous</a>', self.request('GET', f'/w/{token}/log?page=2')[1])
        self.request('POST', f'/w/{token}/policy', {'policy': '{"version":1,"rules":[]}'})
        page = self.request('GET', f'/w/{token}/policy?version=0')[1]
        self.assertIn('payments.refund', page)
        self.assertIn('Restore version 1', page)
        self.assertEqual(self.request('POST', f'/w/{token}/policy', {'restore': '0'})[0], 200)
        self.assertEqual(self.server.store.read(token)['policy']['current'], app.POLICY)

    def test_local_server_also_requires_host_and_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            server = app.make_server(('127.0.0.1', 0), directory)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def request(host, origin):
                    connection = http.client.HTTPConnection('127.0.0.1', server.server_port)
                    try:
                        headers = {'Host': host, 'Content-Type': 'application/x-www-form-urlencoded'}
                        if origin is not None:
                            headers['Origin'] = origin
                        connection.request('POST', '/new', 'sample=0', headers)
                        response = connection.getresponse()
                        response.read()
                        return response.status
                    finally:
                        connection.close()
                self.assertEqual(request('evil.example', 'https://evil.example'), 421)
                self.assertEqual(request(server.allowed_host, 'https://evil.example'), 403)
                self.assertEqual(request(server.allowed_host, None), 403)
                self.assertEqual(request(server.allowed_host, server.origin), 303)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(3)


if __name__ == '__main__':
    unittest.main()
