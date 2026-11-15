import contextlib
import copy
import hashlib
import html
import http.client
import io
import json
import re
import socket
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

import demo
from agentgate.audit import DemoAuditLog
from agentgate.clock import FakeClock
from agentgate.identity import AgentRegistry, AuthError
from agentgate.policy import PolicyEngine, PolicyError
from agentgate.sample_data import POLICY
from agentgate.sbom import generate
from agentgate.tokens import TokenError


class EndToEndDemoTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        # Explicitly exercise ordinary security defaults, including PORT=0.
        self.server = demo.make_server(('127.0.0.1', 0), clock=self.clock)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = None
        self.csrf = None

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)

    def request(self, method, path, body=None, headers=None):
        headers = dict(headers or {})
        if self.cookie:
            headers['Cookie'] = self.cookie
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            data = response.read().decode()
            if response.getheader('Set-Cookie'):
                self.cookie = response.getheader('Set-Cookie').split(';', 1)[0]
            self.assertEqual(response.getheader('X-Content-Type-Options'), 'nosniff')
            self.assertIn("default-src 'none'", response.getheader('Content-Security-Policy'))
            match = re.search(r'name=csrf value="([^"]+)"', data)
            if match:
                self.csrf = html.unescape(match.group(1))
            return response.status, data
        finally:
            conn.close()

    def form(self, path, values=None):
        values = dict(values or {})
        values['csrf'] = self.csrf or ''
        return self.request('POST', path, urlencode(values), {'Content-Type': 'application/x-www-form-urlencoded'})

    def api(self, path, payload, token=None):
        headers = {'Content-Type': 'application/json', 'X-CSRF-Token': self.csrf or ''}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        status, text = self.request('POST', path, json.dumps(payload), headers)
        return status, json.loads(text)

    def agents(self):
        status, page = self.request('GET', '/agents')
        self.assertEqual(status, 200)
        rows = re.findall(r'<tr><td>([^<]+)</td><td>(agt_[^<]+)</td><td><code>([^<]+)</code>', page)
        return {html.unescape(name): (agent_id, html.unescape(secret)) for name, agent_id, secret in rows}

    def issue(self, agent, scopes):
        status, page = self.form('/token', {'agent_id': agent[0], 'client_secret': agent[1], 'scopes': scopes})
        self.assertEqual(status, 200, page)
        self.assertIn('Decoded claims', page)
        self.assertIn('Expires:', page)
        token = re.search(r'agt1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', page).group()
        return token

    def call(self, agent_id, tool='payments.refund', arguments='amount=40\ncurrency=EUR\norder_id=ORD-1001'):
        status, page = self.form('/call', {'agent_id': agent_id, 'tool': tool, 'arguments': arguments})
        self.assertEqual(status, 200, page)
        return page

    @property
    def box(self):
        return self.server.state.boxes[self.cookie.split('=', 1)[1]]

    def test_full_browser_and_mcp_flow_with_fakes(self):
        agents = self.agents()
        invoice = agents['invoice-bot']
        support = agents['support-triage']
        self.assertNotIn(invoice[1], self.request('GET', '/agents')[1])
        status, page = self.request('GET', '/token')
        self.assertEqual(status, 200)
        self.assertIn('action=/token', page)
        self.assertIn('name=client_secret', page)
        token = self.issue(invoice, 'crm.lookup_account,payments.refund,email.send')
        claims = self.box.tokens.verify(token)
        self.assertEqual(claims['exp'] - claims['iat'], 300)
        self.assertNotIn('email.send', claims['scp'])
        self.assertIn('queued', self.call(invoice[0]))
        self.assertIn('constraint_failed:amount.max', self.call(invoice[0], arguments='amount=400\ncurrency=EUR\norder_id=O'))
        self.assertIn('out_of_scope', self.call(invoice[0], 'email.send', 'body=sample'))

        status, listed = self.api('/api/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}, token)
        self.assertEqual(status, 200)
        self.assertEqual({tool['name'] for tool in listed['result']['tools']}, set(claims['scp']))
        request = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'payments.refund', 'arguments': {'amount': 40, 'currency': 'EUR', 'order_id': 'O'}}}
        status, result = self.api('/api/mcp', request, token)
        self.assertEqual(status, 200)
        self.assertTrue(result['result']['allowed'])

        changed = copy.deepcopy(POLICY)
        changed['rules'].append({'agent': invoice[0], 'tool': 'payments.refund', 'effect': 'deny'})
        self.assertEqual(self.form('/policy', {'policy': json.dumps(changed)})[0], 200)
        self.assertIn('explicit_deny', self.call(invoice[0]))
        self.assertEqual(self.form('/policy', {'policy': json.dumps(POLICY)})[0], 200)
        self.issue(support, 'files.read')
        secret = 'sk-do-not-store-this-value'
        self.assertIn('secret_in_args', self.call(support[0], 'files.read', 'path=' + secret))
        self.assertNotIn(secret, self.box.audit.export_jsonl())
        unknown_tool = 'person@example.test-' + secret + 'x' * 2000
        self.assertIn('out_of_scope', self.call(invoice[0], unknown_tool, ''))
        entries = [json.loads(line) for line in self.box.audit.export_jsonl().splitlines()]
        self.assertEqual(entries[-1]['tool'], '<withheld>')
        self.assertNotIn(secret, repr(entries))

        self.assertEqual(self.form('/keys/rotate')[0], 200)
        self.assertEqual(self.box.tokens.verify(token)['sub'], invoice[0])
        self.assertIn('queued', self.call(invoice[0]))
        self.assertEqual(self.form('/token/revoke', {'agent_id': invoice[0]})[0], 200)
        self.assertIn('invalid_token', self.call(invoice[0]))
        token = self.issue(invoice, 'payments.refund')
        self.assertEqual(self.form('/agents/revoke', {'agent_id': invoice[0]})[0], 200)
        self.assertIn('invalid_token', self.call(invoice[0]))
        self.assertIn('✓', self.form('/audit/verify')[1])
        self.assertIn('Tamper (demo)', self.request('GET', '/audit')[1])
        self.assertEqual(self.form('/audit/tamper', {'index': '0'})[0], 200)
        self.assertIn('✗ chain broken at index 0', self.form('/audit/verify')[1])

        self.assertEqual(self.form('/agents', {'name': 'new-bot'})[0], 200)
        newcomer = self.agents()['new-bot']
        custom = {'version': 1, 'rules': [{'agent': newcomer[0], 'tool': 'files.read', 'effect': 'allow', 'constraints': {'path': {'prefix': '/srv/reports/', 'max_len': 256}}}]}
        self.assertEqual(self.form('/policy', {'policy': json.dumps(custom)})[0], 200)
        self.issue(newcomer, 'files.read')
        self.assertIn('Q3 summary', self.call(newcomer[0], 'files.read', 'path=/srv/reports/sample.txt'))
        self.clock.advance(306)
        self.assertIn('invalid_token', self.call(newcomer[0], 'files.read', 'path=/srv/reports/sample.txt'))

    def test_port_zero_has_no_test_privileges(self):
        self.agents()
        self.assertFalse(self.server.state.test_mode)
        with self.assertRaises(AttributeError):
            _ = self.box.secrets
        status, _ = self.request('POST', '/agents', urlencode({'name': 'blocked'}), {'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(status, 403)
        status, _ = self.request('POST', '/api/token', '{}', {'Content-Type': 'application/json'})
        self.assertEqual(status, 403)

    def test_malformed_inputs_and_full_audit_never_log_addresses(self):
        invoice = self.agents()['invoice-bot']
        token = self.issue(invoice, 'payments.refund')
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            for path in ('/api/token', '/api/mcp'):
                for raw in ('[' * 64000, '{"x":' + '9' * 5000 + '}', '{"x":' + '[' * 40 + '0' + ']' * 40 + '}'):
                    status, _ = self.request('POST', path, raw, {'Content-Type': 'application/json', 'X-CSRF-Token': self.csrf})
                    self.assertEqual(status, 400)
            status, _ = self.form('/policy', {'policy': '[' * 2000})
            self.assertEqual(status, 400)
            self.box.audit.limit = len(self.box.audit.entries)
            with patch.object(self.box.connector, 'invoke', wraps=self.box.connector.invoke) as invoke:
                self.assertIn('audit_failure', self.call(invoice[0]))
                invoke.assert_not_called()
            status, _ = self.form('/token', {'agent_id': invoice[0], 'client_secret': invoice[1], 'scopes': 'payments.refund'})
            self.assertEqual(status, 429)
            status, _ = self.api('/api/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}, token)
            self.assertEqual(status, 200)
        self.assertEqual(captured.getvalue(), '')
        self.assertEqual(self.request('GET', '/healthz'), (200, 'ok'))

    def test_browser_token_rate_limit(self):
        invoice = self.agents()['invoice-bot']
        self.box.hits['tokens'] = [time.monotonic()] * 10
        with patch.object(self.box.registry, 'authenticate') as authenticate:
            status, _ = self.form('/token', {'agent_id': invoice[0], 'client_secret': invoice[1], 'scopes': 'payments.refund'})
            self.assertEqual(status, 429)
            authenticate.assert_not_called()

    def test_cra_does_not_generate_or_publish_inventory(self):
        with patch('agentgate.sbom.generate', side_effect=AssertionError('must not scan deployment')):
            status, page = self.request('GET', '/cra')
        self.assertEqual(status, 200)
        self.assertNotIn('"components"', page)
        self.assertNotIn('"hashes"', page)


class RegressionTests(unittest.TestCase):
    def test_atomic_rate_limit_and_unique_names(self):
        clock = FakeClock()
        registry = AgentRegistry(clock)
        agent, _ = registry.register('invoice-bot')
        with self.assertRaisesRegex(ValueError, 'duplicate_name'):
            registry.register('invoice-bot')
        registry.revoke(agent.agent_id)
        with self.assertRaisesRegex(ValueError, 'duplicate_name'):
            registry.register('invoice-bot')
        policy = PolicyEngine(clock, POLICY)
        barrier = threading.Barrier(16)
        def call(_):
            barrier.wait()
            return policy.evaluate(agent, 'payments.refund', {'amount': 40, 'currency': 'EUR', 'order_id': 'O'})
        with ThreadPoolExecutor(max_workers=16) as pool:
            decisions = list(pool.map(call, range(16)))
        self.assertEqual(sum(item.allowed for item in decisions), 5)
        self.assertEqual(sum(item.reason == 'rate_limited' for item in decisions), 11)
        policy.load(POLICY)
        self.assertEqual(policy.evaluate(agent, 'payments.refund', {'amount': 40, 'currency': 'EUR', 'order_id': 'O'}).reason, 'rate_limited')
        clock.advance(61)
        self.assertTrue(policy.evaluate(agent, 'payments.refund', {'amount': 40, 'currency': 'EUR', 'order_id': 'O'}).allowed)

    def test_unknown_and_known_credentials_use_same_work_factor(self):
        registry = AgentRegistry(FakeClock())
        agent, _ = registry.register('test-bot')
        original = hashlib.pbkdf2_hmac
        with patch('agentgate.identity.hashlib.pbkdf2_hmac', wraps=original) as pbkdf:
            for client_id in (agent.agent_id, 'agt_unknown'):
                with self.assertRaises(AuthError):
                    registry.authenticate(client_id, 'wrong')
            self.assertEqual([call.args[3] for call in pbkdf.call_args_list], [200000, 200000])

    def test_export_roundtrip_and_tamper(self):
        audit = DemoAuditLog(FakeClock(), demo_tamper_enabled=True)
        entry = audit.append('tool.call', 'agt_4040404040404040', args={'amount': 40})
        exported = audit.export_jsonl()
        self.assertNotIn('40', exported)
        self.assertEqual(json.loads(exported), asdict(entry))
        self.assertEqual(audit.verify(), (True, None))
        audit._tamper_for_demo(0)
        self.assertEqual(audit.verify(), (False, 0))

    def test_deep_policy_raises_domain_error(self):
        policy = PolicyEngine(FakeClock(), POLICY)
        with self.assertRaises(PolicyError):
            policy.load('[' * 2000)
        with self.assertRaises(PolicyError):
            policy.load('{"version":1,"rules":[],"x":' + '9' * 5000 + '}')

    def test_sessions_are_cheap_bounded_and_independent_of_proxy_ip(self):
        state = demo.DemoState()
        with patch('agentgate.identity.hashlib.pbkdf2_hmac', side_effect=AssertionError('session creation must be cheap')):
            first, first_sid = state.sandbox(None, 'same-proxy')
            # Return each issued SID to confirm the session. One-shot sessions
            # are provisional and may be evicted, so they cannot exercise the
            # capacity rejection for a table containing only active sessions.
            self.assertIs(state.sandbox(first_sid, 'same-proxy')[0], first)
            for _ in range(499):
                box, sid = state.sandbox(None, 'same-proxy')
                self.assertIs(state.sandbox(sid, 'same-proxy')[0], box)
        self.assertEqual(len(state.boxes), 500)
        self.assertTrue(all(box.visits >= 2 for box in state.boxes.values()))
        existing_sids = tuple(state.boxes)
        for source in ('same-proxy', 'another-source'):
            with self.assertRaisesRegex(RuntimeError, 'session_capacity'):
                state.sandbox(None, source)
            self.assertEqual(tuple(state.boxes), existing_sids)
        self.assertIs(state.sandbox(first_sid, 'same-proxy')[0], first)
        self.assertFalse(hasattr(state, 'creation_hits'))
        first.touched -= 1801
        state.sandbox(None, 'another-source')
        self.assertNotIn(first_sid, state.boxes)
        self.assertEqual(len(state.boxes), 500)

    def test_sbom_only_contains_project_artifacts(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path / 'demo.py').write_text('print("demo")\n')
            (path / 'private.env').write_text('private deployment data')
            (path / 'agentgate').mkdir()
            (path / 'agentgate' / '__init__.py').write_text('')
            (path / 'agentgate' / 'link.py').symlink_to(path / 'private.env')
            names = {item['name'] for item in generate(root)['components']}
            self.assertEqual(names, {'python', 'demo.py', 'agentgate/__init__.py'})

    def test_idle_and_incomplete_body_connections_are_bounded(self):
        server = demo.make_server(('127.0.0.1', 0), max_workers=1, request_timeout=0.2)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        captured = io.StringIO()
        try:
            with contextlib.redirect_stderr(captured):
                for initial in (b'', b'POST /api/token HTTP/1.0\r\nContent-Length: 10\r\n\r\nx'):
                    sock = socket.create_connection(('127.0.0.1', server.server_port), timeout=2)
                    try:
                        if initial:
                            sock.sendall(initial)
                        self.assertEqual(sock.recv(1024), b'')
                    finally:
                        sock.close()
                # A held worker permit prevents any handler from being started.
                deadline = time.monotonic() + 2
                while not server.slots.acquire(blocking=False):
                    if time.monotonic() > deadline:
                        self.fail('worker permit was not released')
                    time.sleep(0.01)
                try:
                    sock = socket.create_connection(('127.0.0.1', server.server_port), timeout=2)
                    try:
                        self.assertEqual(sock.recv(1024), b'')
                    finally:
                        sock.close()
                finally:
                    server.slots.release()
            self.assertEqual(captured.getvalue(), '')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)


if __name__ == '__main__':
    unittest.main()
