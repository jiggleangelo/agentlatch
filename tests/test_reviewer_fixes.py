import http.client
import json
import threading
import time
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

import demo
from agentgate.audit import DemoAuditLog
from agentgate.clock import FakeClock
from agentgate.connectors import FakeConnector
from agentgate.gateway import Gateway
from agentgate.identity import AgentRegistry, AuthError
from agentgate.keys import KeyRing
from agentgate.policy import PolicyEngine
from agentgate.sample_data import POLICY
from agentgate.tokens import TokenError, TokenService


class ReviewerFixTests(unittest.TestCase):
    def test_argument_and_audit_entry_memory_is_bounded(self):
        with self.assertRaisesRegex(ValueError, 'invalid_arguments'):
            demo.Handler._arguments('\n'.join(f'key{i}=value' for i in range(17)))
        with self.assertRaisesRegex(ValueError, 'invalid_arguments'):
            demo.Handler._arguments('path=' + 'x' * 1025)
        self.assertFalse(Gateway.arguments_valid({f'key{i}': i for i in range(17)}))
        audit = DemoAuditLog(FakeClock())
        entry = audit.append('tool.call', 'agent', args={f'attacker-key-{i}': 'x' * 5000 for i in range(1000)})
        encoded = json.dumps(asdict(entry), sort_keys=True, separators=(',', ':')).encode()
        self.assertLessEqual(len(encoded), audit.MAX_ENTRY_BYTES + 80)
        self.assertLessEqual(len(entry.args), audit.MAX_CONTAINER_ITEMS + 1)

    def test_key_rotation_is_bounded_and_retires_old_tokens(self):
        clock = FakeClock()
        registry = AgentRegistry(clock)
        agent, _ = registry.register('invoice-bot')
        keys = KeyRing()
        service = TokenService(keys, registry, clock)
        token, _ = service.issue(agent, ['payments.refund'])
        keys.rotate()
        keys.rotate()
        self.assertEqual(service.verify(token)['sub'], agent.agent_id)
        keys.rotate()
        with self.assertRaises(TokenError):
            service.verify(token)
        for _ in range(1000):
            keys.rotate()
            self.assertLessEqual(len(keys._keys), 3)
            self.assertTrue(all(len(kid) == 32 for kid in keys._keys))
        current, _ = service.issue(agent, ['payments.refund'])
        self.assertEqual(service.verify(current)['sub'], agent.agent_id)

    def test_process_wide_audit_budget_is_released_on_eviction(self):
        state = demo.DemoState()
        state.audit_capacity.limit = 3
        box, sid = state.sandbox(None)
        box.ensure_seeded()
        self.assertEqual(state.audit_capacity.used, 3)
        with self.assertRaisesRegex(RuntimeError, 'global_audit_limit'):
            box.audit.append('event', 'agent')
        box.touched -= 61
        replacement, _ = state.sandbox(None)
        self.assertNotIn(sid, state.boxes)
        self.assertEqual(state.audit_capacity.used, 0)
        replacement.audit.append('event', 'agent')
        self.assertEqual(state.audit_capacity.used, 1)
        with self.assertRaisesRegex(RuntimeError, 'audit_closed'):
            box.audit.append('event', 'agent')
        box.audit.close()
        self.assertEqual(state.audit_capacity.used, 1)

    def test_filling_other_audits_does_not_block_new_session_flow(self):
        state = demo.DemoState()
        self.assertEqual(state.audit_capacity.limit, demo.SESSION_LIMIT * demo.SESSION_AUDIT_LIMIT)
        for _ in range(50):
            attacker, sid = state.sandbox(None)
            state.sandbox(sid)
            for _ in range(demo.SESSION_AUDIT_LIMIT):
                attacker.audit.append('event', 'attacker')
            with self.assertRaisesRegex(RuntimeError, 'audit_limit'):
                attacker.audit.append('event', 'attacker')
        self.assertEqual(state.audit_capacity.used, 10000)
        victim, _ = state.sandbox(None)
        victim.ensure_seeded()
        agent = next(a for a in victim.registry.agents.values() if a.name == 'invoice-bot')
        token, _ = victim.gateway.issue_token(agent.agent_id, victim.pending_secrets[agent.agent_id], ['payments.refund'])
        result = victim.gateway.call(token, 'payments.refund', {'amount': 40, 'currency': 'EUR', 'order_id': 'O'})
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, 'allowed')
        while victim.audit.entry_count() < demo.SESSION_AUDIT_LIMIT:
            victim.audit.append('event', 'victim')
        self.assertEqual(victim.audit.verify(), (True, None))

    def test_audit_close_serializes_with_inflight_append(self):
        capacity = demo.AuditCapacity(10)
        audit = demo.BoundedDemoAuditLog(FakeClock(), capacity=capacity)
        reserved = threading.Event()
        proceed = threading.Event()
        errors = []
        original = capacity.reserve

        def reserve():
            original()
            reserved.set()
            if not proceed.wait(2):
                raise AssertionError('append was not released')

        def append():
            try:
                audit.append('event', 'agent')
            except Exception as exc:
                errors.append(exc)

        with patch.object(capacity, 'reserve', side_effect=reserve):
            writer = threading.Thread(target=append)
            writer.start()
            try:
                self.assertTrue(reserved.wait(2))
                closer = threading.Thread(target=audit.close)
                closer.start()
            finally:
                proceed.set()
                writer.join(3)
            closer.join(3)
        self.assertFalse(writer.is_alive())
        self.assertFalse(closer.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(capacity.used, 0)
        with self.assertRaisesRegex(RuntimeError, 'audit_closed'):
            audit.append('event', 'agent')

    def test_audit_export_supports_bounded_pages(self):
        audit = DemoAuditLog(FakeClock())
        for index in range(125):
            audit.append('event', 'agent', reason=str(index))
        first = audit.export_jsonl(0, demo.AUDIT_PAGE_SIZE).splitlines()
        last = audit.export_jsonl(100, demo.AUDIT_PAGE_SIZE).splitlines()
        self.assertEqual(len(first), 50)
        self.assertEqual(len(last), 25)
        self.assertEqual(json.loads(first[0])['index'], 0)
        self.assertEqual(json.loads(last[0])['index'], 100)
        with self.assertRaises(ValueError):
            audit.export_jsonl(0, 201)

    def test_session_creation_is_cheap_and_seed_credentials_are_fresh(self):
        with patch('agentgate.identity.hashlib.pbkdf2_hmac', side_effect=AssertionError('session creation must not hash')):
            state = demo.DemoState()
            first, _ = state.sandbox(None)
            second, _ = state.sandbox(None)
        first.ensure_seeded()
        second.ensure_seeded()
        first_agents = {agent.name: agent for agent in first.registry.agents.values()}
        second_agents = {agent.name: agent for agent in second.registry.agents.values()}
        self.assertEqual(set(first_agents), set(demo.AGENTS))
        for name in demo.AGENTS:
            left, right = first_agents[name], second_agents[name]
            left_secret = first.pending_secrets[left.agent_id]
            right_secret = second.pending_secrets[right.agent_id]
            self.assertNotEqual(left_secret, right_secret)
            self.assertNotEqual(left.salt, right.salt)
            self.assertNotEqual(left.secret_hash, right.secret_hash)
            self.assertIs(second.registry.authenticate(right.agent_id, right_secret), right)
            with self.assertRaises(AuthError):
                second.registry.authenticate(right.agent_id, left_secret)
        pending = dict(first.pending_secrets)
        with patch.object(first.registry, 'register', side_effect=AssertionError('must not reseed')):
            first.ensure_seeded()
        self.assertEqual(first.pending_secrets, pending)
        self.assertFalse(hasattr(state, 'seed_templates'))

    def test_cookieless_sessions_evict_lru_provisional_session(self):
        state = demo.DemoState()
        _, first_sid = state.sandbox(None)
        for _ in range(499):
            state.sandbox(None)
        _, replacement_sid = state.sandbox(None)
        self.assertEqual(len(state.boxes), 500)
        self.assertNotIn(first_sid, state.boxes)
        self.assertIn(replacement_sid, state.boxes)

    def test_full_table_of_confirmed_sessions_rejects_strangers(self):
        state = demo.DemoState()
        first, first_sid = state.sandbox(None)
        state.sandbox(first_sid)
        for _ in range(499):
            _, sid = state.sandbox(None)
            state.sandbox(sid)
        self.assertTrue(all(box.visits >= 2 for box in state.boxes.values()))
        existing_sids = tuple(state.boxes)
        for source in (None, 'same-proxy', 'another-source'):
            with self.assertRaisesRegex(RuntimeError, 'session_capacity'):
                state.sandbox(None, source)
            self.assertEqual(tuple(state.boxes), existing_sids)
        self.assertIs(state.sandbox(first_sid)[0], first)

    def test_every_invalid_token_denial_is_audited_past_old_limit(self):
        clock = FakeClock()
        registry = AgentRegistry(clock)
        audit = DemoAuditLog(clock, limit=100)
        tokens = TokenService(KeyRing(), registry, clock)
        policy = PolicyEngine(clock, POLICY)
        gateway = Gateway(registry, tokens, policy, audit, FakeConnector(tokens), unauthenticated_audit_limit=20)
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}
        for _ in range(25):
            self.assertEqual(gateway.mcp(request, 'invalid')['error']['message'], 'Unauthorised')
        self.assertEqual(audit.entry_count(), 25)
        self.assertTrue(all(entry.reason == 'invalid_token' for entry in audit.entries))

    def test_verify_result_is_cached_and_invalidated_by_tamper(self):
        audit = DemoAuditLog(FakeClock(), demo_tamper_enabled=True)
        for _ in range(100):
            audit.append('event', 'agent')
        with patch.object(audit, '_hash', wraps=audit._hash) as hash_entry:
            self.assertEqual(audit.verify(), (True, None))
            self.assertEqual(audit.verify(), (True, None))
            self.assertEqual(hash_entry.call_count, 0)
            audit._tamper_for_demo(50)
            self.assertEqual(audit.verify(), (False, 50))
            first_cost = hash_entry.call_count
            self.assertGreater(first_cost, 0)
            self.assertEqual(audit.verify(), (False, 50))
            self.assertEqual(hash_entry.call_count, first_cost)

    def test_audit_verify_has_separate_rate_limit(self):
        state = demo.DemoState()
        box, _ = state.sandbox(None)
        for _ in range(5):
            box.admit('audit_verify', 5)
        with self.assertRaisesRegex(RuntimeError, 'rate_limited'):
            box.admit('audit_verify', 5)

    def test_hash_slot_contention_waits_instead_of_failing_fast(self):
        original_slots = AgentRegistry._hash_slots
        original_wait = AgentRegistry.HASH_WAIT_SECONDS
        slots = threading.BoundedSemaphore(1)
        AgentRegistry._hash_slots = slots
        AgentRegistry.HASH_WAIT_SECONDS = 1.0
        slots.acquire()
        released = threading.Event()

        def release_later():
            time.sleep(0.05)
            slots.release()
            released.set()

        thread = threading.Thread(target=release_later)
        thread.start()
        try:
            started = time.monotonic()
            digest = AgentRegistry._hash('secret', b'0' * 16)
            self.assertTrue(released.is_set())
            self.assertGreaterEqual(time.monotonic() - started, 0.04)
            self.assertEqual(len(digest), 32)
        finally:
            thread.join()
            AgentRegistry._hash_slots = original_slots
            AgentRegistry.HASH_WAIT_SECONDS = original_wait

    def test_host_override_is_used_for_container_deployment(self):
        self.assertEqual(demo.listen_address_from_env({}), ('127.0.0.1', 8080))
        self.assertEqual(demo.listen_address_from_env({'HOST': '0.0.0.0', 'PORT': '9000'}), ('0.0.0.0', 9000))
        with self.assertRaises(ValueError):
            demo.listen_address_from_env({'HOST': 'bad host', 'PORT': '8080'})

    def test_non_loopback_cli_requires_secure_cookies(self):
        self.assertFalse(demo.server_options_from_env({})['secure_cookies'])
        for host in ('0.0.0.0', '::', '192.0.2.10', 'demo.example.test'):
            with self.subTest(host=host):
                with self.assertRaisesRegex(ValueError, 'AGENTGATE_TLS=1'):
                    demo.server_options_from_env({'HOST': host})
                options = demo.server_options_from_env({'HOST': host, 'AGENTGATE_TLS': '1'})
                self.assertTrue(options['secure_cookies'])
                self.assertEqual(options['address'], (host, 8080))
        with patch.dict('os.environ', {'HOST': '0.0.0.0'}, clear=True), patch('demo.make_server') as make:
            with self.assertRaises(ValueError):
                demo.main()
            make.assert_not_called()


class ReviewerHTTPTests(unittest.TestCase):
    def setUp(self):
        self.server = demo.make_server(('127.0.0.1', 0), secure_cookies=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)

    def request(self, method='GET', path='/', cookie=None, values=None):
        headers = {}
        if cookie:
            headers['Cookie'] = cookie
        body = None
        if values is not None:
            body = urlencode(values)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            return response.status, response.read().decode(), dict(response.getheaders())
        finally:
            conn.close()

    def test_cookieless_http_flood_preserves_confirmed_sessions(self):
        with patch.object(demo, 'SESSION_LIMIT', 2):
            cookies = []
            for _ in range(2):
                status, _, headers = self.request()
                self.assertEqual(status, 200)
                cookie = headers['Set-Cookie'].split(';', 1)[0]
                cookies.append(cookie)
                self.assertEqual(self.request(cookie=cookie)[0], 200)
            existing = dict(self.server.state.boxes)
            for _ in range(10):
                status, _, headers = self.request()
                self.assertEqual(status, 429)
                self.assertNotIn('Set-Cookie', headers)
            self.assertEqual(dict(self.server.state.boxes), existing)
            for cookie in cookies:
                self.assertEqual(self.request(cookie=cookie)[0], 200)

    def test_secure_cookie_attributes(self):
        status, _, headers = self.request()
        self.assertEqual(status, 200)
        attributes = headers['Set-Cookie'].split('; ')
        for required in ('Secure', 'HttpOnly', 'SameSite=Strict', 'Path=/'):
            self.assertIn(required, attributes)

    def test_rotate_endpoint_retires_old_key_and_stays_bounded(self):
        status, _, headers = self.request()
        self.assertEqual(status, 200)
        cookie = headers['Set-Cookie'].split(';', 1)[0]
        box = self.server.state.boxes[cookie.split('=', 1)[1]]
        kid, signature = box.keys.sign(b'test')
        # The ring stores the current key plus two predecessors. Starting with
        # K0, exactly three rotations produce [K1, K2, K3] and retire K0.
        # Twenty rotations add no coverage and exceed the endpoint's deliberate
        # per-session request allowance, so a 429 is the correct old result.
        for _ in range(3):
            status, page, _ = self.request('POST', '/keys/rotate', cookie, {'csrf': box.csrf})
            self.assertEqual(status, 200)
            self.assertIn('newest three keys', page)
            self.assertLessEqual(len(box.keys._keys), 3)
        self.assertFalse(box.keys.verify(kid, b'test', signature))


class DeploymentConfigurationTests(unittest.TestCase):
    # These are configuration regression tests, not evidence of a live proxy.
    ROOT = Path(__file__).resolve().parents[1]

    def test_container_requires_https_proxy_and_private_backend(self):
        config = json.loads((self.ROOT / 'compose.yaml').read_text())
        app = config['services']['demo']
        edge = config['services']['edge']
        self.assertEqual(app['environment']['HOST'], '0.0.0.0.0'.replace('0.0.0.0.0', '0.0.0.0'))
        self.assertEqual(app['environment']['AGENTGATE_TLS'], '1')
        self.assertEqual(app['environment']['PORT'], '8080')
        self.assertNotIn('ports', app)
        self.assertEqual(app['networks'], ['backend'])
        self.assertTrue(config['networks']['backend']['internal'])
        self.assertEqual(edge['ports'], ['443:443'])
        self.assertIn('backend', edge['networks'])
        certificates = next(item for item in edge['volumes'] if item['target'] == '/etc/nginx/tls')
        self.assertIn('${AGENTGATE_CERT_DIR:?', certificates['source'])
        self.assertTrue(certificates['read_only'])

    def test_edge_buffers_slow_requests_and_limits_worker_admission(self):
        config = (self.ROOT / 'deploy/nginx.conf').read_text()
        for directive in (
            'listen 443 ssl;',
            'ssl_certificate /etc/nginx/tls/fullchain.pem;',
            'ssl_certificate_key /etc/nginx/tls/privkey.pem;',
            'limit_conn_zone $binary_remote_addr zone=per_client:1m;',
            'limit_conn_zone $server_name zone=all_clients:1m;',
            'limit_conn per_client 4;',
            'limit_conn all_clients 12;',
            'limit_conn_status 429;',
            'limit_req_status 429;',
            'client_header_timeout 5s;',
            'client_body_timeout 5s;',
            # The product accepts catalogue uploads up to 1 MiB. A 64 KiB
            # proxy cap would reject valid brief-compliant inputs.
            'client_max_body_size 1m;',
            'proxy_request_buffering on;',
            'proxy_buffering on;',
            'proxy_set_header Connection close;',
            'proxy_pass http://application;',
            'server demo:8080;',
            'access_log off;',
            'error_log /dev/null;',
        ):
            with self.subTest(directive=directive):
                self.assertIn(directive, config)
        self.assertNotIn('listen 80;', config)
        self.assertNotIn('proxy_request_buffering off;', config)
        server = demo.make_server(('127.0.0.1', 0))
        try:
            self.assertLess(12, server.max_workers)
        finally:
            server.server_close()


if __name__ == '__main__':
    unittest.main()
