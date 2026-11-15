import datetime
import html
import ipaddress
import json
import os
import secrets
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from agentgate.audit import DemoAuditLog
from agentgate.clock import SystemClock
from agentgate.connectors import FakeConnector
from agentgate.gateway import Gateway
from agentgate.identity import AgentRegistry, AuthError
from agentgate.keys import KeyRing
from agentgate.metering import Metering
from agentgate.policy import PolicyEngine, PolicyError
from agentgate.sample_data import AGENTS, POLICY
from agentgate.tokens import TokenError, TokenService

BANNER = 'Demo operated by AI agents. Made-up data. Do not enter real personal data. Nothing is charged.'
CSS = 'body{font:16px system-ui;max-width:960px;margin:auto;padding:1rem;color:#17202a}.banner{background:#fff3cd;border:1px solid #e0b400;padding:1rem}nav a{margin-right:1rem}pre{white-space:pre-wrap;background:#f4f6f7;padding:1rem;overflow-wrap:anywhere}input,textarea,select,button{padding:.5rem;margin:.25rem}table{border-collapse:collapse}td,th{padding:.4rem;border:1px solid #bbb}.ok{color:#087830}.bad{color:#b00020}'
CRA = 'Readiness, not compliance. Run python3 -m agentgate.sbom locally for source hashes and python3 -m agentgate.release_check for the human-evidence release gate. No deployment file inventory is published here. Product release remains blocked pending human evidence.'
AUDIT_PAGE_SIZE = 50
SESSION_LIMIT = 500
SESSION_AUDIT_LIMIT = 200
GLOBAL_AUDIT_ENTRY_LIMIT = SESSION_LIMIT * SESSION_AUDIT_LIMIT


def esc(value):
    return html.escape(str(value), quote=True)


def layout(title, body):
    links = ''.join('<a href="' + path + '">' + label + '</a>' for path, label in (
        ('/', 'Home'), ('/agents', 'Agents'), ('/token', 'Token'), ('/call', 'Call'),
        ('/policy', 'Policy'), ('/audit', 'Audit'), ('/partner', 'Partner'), ('/cra', 'CRA')))
    return '<!doctype html><html><head><meta charset=utf-8><title>' + esc(title) + '</title><link rel=stylesheet href=/static/app.css></head><body><div class="banner" role="alert">' + esc(BANNER) + '</div><nav>' + links + '</nav><main><h1>' + esc(title) + '</h1>' + body + '</main></body></html>'


def decode_json(raw):
    value = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
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


class AuditCapacity:
    def __init__(self, limit=GLOBAL_AUDIT_ENTRY_LIMIT):
        self.limit = limit
        self.used = 0
        self.lock = threading.Lock()

    def reserve(self):
        with self.lock:
            if self.used >= self.limit:
                raise RuntimeError('global_audit_limit')
            self.used += 1

    def release(self, count):
        with self.lock:
            self.used = max(0, self.used - count)


class BoundedDemoAuditLog(DemoAuditLog):
    def __init__(self, *args, capacity, **kwargs):
        super().__init__(*args, **kwargs)
        self.capacity = capacity
        self._reserved = 0
        self._closed = False

    def append(self, *args, **kwargs):
        with self._lock:
            if self._closed:
                raise RuntimeError('audit_closed')
            if len(self.entries) >= self.limit:
                raise RuntimeError('audit_limit')
            self.capacity.reserve()
            try:
                entry = super().append(*args, **kwargs)
            except Exception:
                self.capacity.release(1)
                raise
            self._reserved += 1
            return entry

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self.capacity.release(self._reserved)
            self._reserved = 0


class Sandbox:
    def __init__(self, capacity, test_mode=False, demo_tamper=True, clock=None):
        self.clock = clock or SystemClock()
        self.lock = threading.RLock()
        self.registry = AgentRegistry(self.clock)
        self.audit = BoundedDemoAuditLog(self.clock, limit=SESSION_AUDIT_LIMIT, capacity=capacity, demo_tamper_enabled=demo_tamper)
        self.keys = KeyRing()
        self.policy = PolicyEngine(self.clock, POLICY)
        self.tokens = TokenService(self.keys, self.registry, self.clock)
        self.metering = Metering(self.clock)
        self.connector = FakeConnector(self.tokens)
        self.gateway = Gateway(self.registry, self.tokens, self.policy, self.audit, self.connector, self.metering)
        self.pending_secrets = {}
        self._test_secrets = {} if test_mode else None
        self.last_tokens = {}
        self.csrf = secrets.token_urlsafe(32)
        self.touched = time.monotonic()
        self.visits = 1
        self.hits = {}

    @property
    def secrets(self):
        if self._test_secrets is None:
            raise AttributeError('test-only secret access is disabled')
        return self._test_secrets

    def admit(self, category, limit):
        now = time.monotonic()
        hits = [stamp for stamp in self.hits.get(category, ()) if stamp > now - 60]
        if len(hits) >= limit:
            raise RuntimeError('rate_limited')
        hits.append(now)
        self.hits[category] = hits

    def ensure_seeded(self):
        with self.lock:
            for name in AGENTS:
                if any(agent.name == name for agent in self.registry.agents.values()):
                    continue
                agent, secret = self.registry.register(name)
                try:
                    self.audit.append('agent.register', agent.agent_id, reason='seeded')
                except Exception:
                    self.registry.agents.pop(agent.agent_id, None)
                    raise
                self.pending_secrets[agent.agent_id] = secret
                if self._test_secrets is not None:
                    self._test_secrets[agent.agent_id] = secret


class DemoState:
    def __init__(self, test_mode=False, demo_tamper=True, clock=None):
        self.lock = threading.Lock()
        self.boxes = OrderedDict()
        self.test_mode = test_mode
        self.demo_tamper = demo_tamper
        self.clock = clock
        self.audit_capacity = AuditCapacity()

    def _discard(self, key):
        box = self.boxes.pop(key)
        box.audit.close()

    def sandbox(self, supplied_sid, source=None):
        with self.lock:
            now = time.monotonic()
            for key in list(self.boxes):
                box = self.boxes[key]
                ttl = 60 if box.visits < 2 else 1800
                if now - box.touched > ttl:
                    self._discard(key)
            if supplied_sid in self.boxes:
                box = self.boxes.pop(supplied_sid)
                box.touched = now
                box.visits += 1
                self.boxes[supplied_sid] = box
                return box, None
            if len(self.boxes) >= SESSION_LIMIT:
                provisional = next((key for key, box in self.boxes.items() if box.visits < 2), None)
                if provisional is None:
                    raise RuntimeError('session_capacity')
                self._discard(provisional)
            sid = secrets.token_hex(16)
            box = Sandbox(self.audit_capacity, self.test_mode, self.demo_tamper, self.clock)
            self.boxes[sid] = box
            return box, sid


class BoundedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, handler, max_workers=16, request_timeout=3):
        self.slots = threading.BoundedSemaphore(max_workers)
        self.max_workers = max_workers
        self.request_timeout = request_timeout
        super().__init__(address, handler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(self.request_timeout)
        return request, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            self.shutdown_request(request)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = 'AgentGateDemo'
    sys_version = ''

    def log_message(self, *args):
        pass

    def handle(self):
        timer = threading.Timer(self.server.request_timeout * 2, self._expire)
        timer.daemon = True
        timer.start()
        try:
            super().handle()
        except (OSError, ValueError, RecursionError):
            pass
        finally:
            timer.cancel()

    def _expire(self):
        try:
            self.connection.shutdown(2)
        except OSError:
            pass

    def _absolute_html_links(self, content):
        base = self.server.public_base_url
        if not base:
            return content
        for attribute in ('href', 'action', 'src'):
            content = content.replace(attribute + '=/', attribute + '=' + base + '/')
            content = content.replace(attribute + '="/', attribute + '="' + base + '/')
            content = content.replace(attribute + "='/", attribute + "='" + base + '/')
        return content

    def _send(self, status, content, kind='text/html; charset=utf-8', cookie=None):
        if kind.startswith('text/html'):
            content = self._absolute_html_links(content)
        data = content.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        if cookie:
            secure = '; Secure' if self.server.secure_cookies else ''
            self.send_header('Set-Cookie', f'sid={cookie}; HttpOnly; SameSite=Strict; Path=/{secure}')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.close_connection = True
        self.wfile.write(data)

    def _json(self, status, value, cookie=None):
        self._send(status, json.dumps(value, separators=(',', ':')), 'application/json; charset=utf-8', cookie)

    def _host_allowed(self):
        if not self.server.allowed_hosts:
            return True
        values = self.headers.get_all('Host', [])
        return len(values) == 1 and values[0].strip().lower() in self.server.allowed_hosts

    def _session(self):
        supplied = None
        for item in self.headers.get('Cookie', '').split(';'):
            key, _, value = item.strip().partition('=')
            if key == 'sid' and len(value) == 32:
                try:
                    bytes.fromhex(value)
                    supplied = value
                except ValueError:
                    pass
        return self.server.state.sandbox(supplied)

    def _body(self):
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
            self._send(411, layout('Length required', '<p>One Content-Length is required.</p>'))
            return None
        try:
            size = int(self.headers['Content-Length'])
        except ValueError:
            size = -1
        if size < 0 or size > 65536:
            self._send(413 if size > 65536 else 400, layout('Bad request', '<p>Invalid or excessive body length.</p>'))
            return None
        body = self.rfile.read(size)
        if len(body) != size:
            raise ValueError('incomplete_body')
        return body

    @staticmethod
    def _form(body):
        values = parse_qs(body.decode(), keep_blank_values=True, max_num_fields=50)
        return {key: items[-1] for key, items in values.items()}

    @staticmethod
    def _arguments(raw):
        if not isinstance(raw, str) or len(raw.encode()) > Gateway.MAX_ARGUMENTS_BYTES:
            raise ValueError('invalid_arguments')
        result = {}
        for line in raw.splitlines():
            if not line.strip():
                continue
            if len(result) >= Gateway.MAX_ARGUMENT_KEYS:
                raise ValueError('invalid_arguments')
            key, separator, value = line.partition('=')
            key, value = key.strip(), value.strip()
            if not separator or not key or len(key.encode()) > Gateway.MAX_ARGUMENT_KEY_BYTES or len(value.encode()) > Gateway.MAX_ARGUMENT_VALUE_BYTES:
                raise ValueError('invalid_arguments')
            try:
                result[key] = decode_json(value)
            except json.JSONDecodeError:
                result[key] = value
        if not Gateway.arguments_valid(result):
            raise ValueError('invalid_arguments')
        return result

    def _csrf_field(self, box):
        return '<input type=hidden name=csrf value="' + esc(box.csrf) + '">'

    def _csrf_ok(self, box, form=None):
        if self.server.state.test_mode:
            return True
        supplied = self.headers.get('X-CSRF-Token') or (form or {}).get('csrf')
        return isinstance(supplied, str) and secrets.compare_digest(supplied, box.csrf)

    def _agent_options(self, box):
        return ''.join('<option value="' + esc(a.agent_id) + '">' + esc(a.name) + (' (revoked)' if a.revoked else '') + '</option>' for a in box.registry.agents.values())

    def _token_form(self, box):
        return '<p>Copy the one-time secret from Agents. Issued credentials are saved for Call in this session.</p><p>The newest three signing keys are retained. Further rotation retires the oldest key and invalidates its tokens.</p><form method=post action=/token>' + self._csrf_field(box) + '<label>Agent <select name=agent_id>' + self._agent_options(box) + '</select></label><label>Client secret <input type=password name=client_secret required autocomplete=off></label><label>Scopes (comma separated) <input name=scopes size=65 value="crm.lookup_account,payments.refund,files.read"></label><button>Issue token</button></form><form method=post action=/keys/rotate>' + self._csrf_field(box) + '<button>Rotate signing key</button></form><form method=post action=/token/revoke>' + self._csrf_field(box) + '<select name=agent_id>' + self._agent_options(box) + '</select><button>Revoke saved token</button></form>'

    def _call_form(self, box, message=''):
        tools = ''.join('<option value="' + esc(t['name']) + '"' + (' selected' if t['name'] == 'payments.refund' else '') + '>' + esc(t['name']) + '</option>' for t in box.connector.list_tools())
        return message + '<p>First issue a token on Token. Blank Bearer uses the saved token for the selected agent.</p><form method=post action=/call>' + self._csrf_field(box) + '<label>Agent <select name=agent_id>' + self._agent_options(box) + '</select></label><label>Tool <select name=tool>' + tools + '</select></label><label>Bearer (optional) <input name=token autocomplete=off></label><textarea name=arguments rows=6 cols=60>amount=40\ncurrency=EUR\norder_id=ORD-1001</textarea><button>Call</button></form>'

    def do_GET(self):
        self._dispatch(False)

    def do_POST(self):
        self._dispatch(True)

    def _dispatch(self, post):
        cookie = None
        try:
            if not self._host_allowed():
                self._send(421, layout('Misdirected request', '<p>The Host header is not permitted.</p>'))
                return
            parsed = urlsplit(self.path)
            path = parsed.path
            if not post and path in ('/healthz', '/static/app.css'):
                self._send(200, 'ok' if path == '/healthz' else CSS, 'text/plain; charset=utf-8' if path == '/healthz' else 'text/css; charset=utf-8')
                return
            body = self._body() if post else None
            if post and body is None:
                return
            box, cookie = self._session()
            if not box.lock.acquire(blocking=False):
                raise RuntimeError('session_busy')
            try:
                box.admit('requests', 120)
                self._post(path, box, cookie, body) if post else self._get(path, parsed.query, box, cookie)
            finally:
                box.lock.release()
        except AuthError:
            self._json(401, {'error': 'invalid_client'}, cookie)
        except TokenError:
            self._json(400, {'error': 'invalid_token_or_scope'}, cookie)
        except (UnicodeError, ValueError, TypeError, RecursionError, PolicyError):
            self._send(400, layout('Bad request', '<p>Invalid input.</p>'), cookie=cookie)
        except RuntimeError:
            self._send(429, layout('Capacity reached', '<p>Session or service capacity reached. Try again later.</p>'), cookie=cookie)
        except OSError:
            self.close_connection = True
        except Exception:
            self._send(500, layout('Unavailable', '<p>Request could not be completed.</p>'), cookie=cookie)

    def _get(self, path, query, box, cookie):
        if path == '/':
            body = '<p>Customer-hosted identity, scoped credentials and policy with fake tools.</p><ol><li>Open Agents and copy a one-time secret.</li><li>Issue a Token and inspect claims/expiry.</li><li>Call payments.refund with amount 40, then 400.</li><li>Edit Policy and repeat using the same token.</li><li>Verify Audit, tamper, then verify again.</li><li>Revoke an agent and repeat its call.</li></ol><p>MCP-shaped, not spec-conformant. Confirmed sessions expire after 30 minutes; one-shot sessions expire after 60 seconds.</p>'
        elif path in ('/agents', '/token', '/call', '/policy', '/audit', '/partner', '/cra'):
            if path in ('/agents', '/token', '/call'):
                box.ensure_seeded()
            if path == '/agents':
                rows = []
                for agent in box.registry.agents.values():
                    secret = box.pending_secrets.pop(agent.agent_id, None)
                    shown = '<code>' + esc(secret) + '</code> (shown once)' if secret else 'already shown'
                    rows.append('<tr><td>' + esc(agent.name) + '</td><td>' + esc(agent.agent_id) + '</td><td>' + shown + '</td><td>' + ('revoked' if agent.revoked else 'active') + '</td></tr>')
                body = '<table><tr><th>Name</th><th>ID</th><th>Secret</th><th>Status</th></tr>' + ''.join(rows) + '</table><form method=post action=/agents>' + self._csrf_field(box) + '<input name=name maxlength=64 required><button>Register</button></form><form method=post action=/agents/revoke>' + self._csrf_field(box) + '<select name=agent_id>' + self._agent_options(box) + '</select><button>Revoke</button></form>'
            elif path == '/token':
                body = self._token_form(box)
            elif path == '/call':
                body = self._call_form(box)
            elif path == '/policy':
                body = '<form method=post action=/policy>' + self._csrf_field(box) + '<textarea name=policy rows=20 cols=90>' + esc(json.dumps(box.policy.data, indent=2)) + '</textarea><button>Load policy</button></form>'
            elif path == '/audit':
                values = parse_qs(query, max_num_fields=2)
                try:
                    page = max(1, int(values.get('page', ['1'])[-1]))
                except (TypeError, ValueError):
                    raise ValueError('invalid_page')
                total = box.audit.entry_count()
                last_page = max(1, (total + AUDIT_PAGE_SIZE - 1) // AUDIT_PAGE_SIZE)
                page = min(page, last_page)
                offset = (page - 1) * AUDIT_PAGE_SIZE
                exported = box.audit.export_jsonl(offset, AUDIT_PAGE_SIZE)
                navigation = '<p>Audit page ' + str(page) + ' of ' + str(last_page) + '. Showing at most ' + str(AUDIT_PAGE_SIZE) + ' entries.</p>'
                if page > 1:
                    navigation += '<a href="/audit?page=' + str(page - 1) + '">Previous</a> '
                if page < last_page:
                    navigation += '<a href="/audit?page=' + str(page + 1) + '">Next</a>'
                body = navigation + '<pre>' + esc(exported) + '</pre><form method=post action=/audit/verify>' + self._csrf_field(box) + '<button>Verify</button></form>'
                if self.server.state.demo_tamper:
                    body += '<form method=post action=/audit/tamper>' + self._csrf_field(box) + '<input name=index type=number min=0 value=0><button>Tamper (demo)</button></form>'
            elif path == '/partner':
                body = '<p>Estimated monthly minimum: €' + esc(box.metering.estimate()) + '. No billing occurs. This demo collects no contact details.</p>'
            else:
                body = '<p>' + esc(CRA) + '</p>'
        else:
            self._send(404, layout('Not found', '<p>The requested page does not exist.</p>'), cookie=cookie)
            return
        self._send(200, layout('AgentGate' if path == '/' else path[1:].title(), body), cookie=cookie)

    def _post(self, path, box, cookie, body):
        if path in ('/api/token', '/api/mcp'):
            if self.headers.get_content_type() != 'application/json':
                self._json(415, {'error': 'unsupported_media_type'}, cookie)
                return
            try:
                payload = decode_json(body)
            except (ValueError, UnicodeError, RecursionError):
                self._json(400, {'error': 'invalid_json'}, cookie)
                return
            if not isinstance(payload, dict):
                self._json(400, {'error': 'invalid_json'}, cookie)
                return
            if path == '/api/token':
                if not self._csrf_ok(box):
                    self._json(403, {'error': 'csrf_failed'}, cookie)
                    return
                box.admit('tokens', 10)
                token, claims = box.gateway.issue_token(payload.get('client_id'), payload.get('client_secret'), payload.get('scope', []))
                self._json(200, {'access_token': token, 'token_type': 'Bearer', 'expires_in': claims['exp'] - claims['iat'], 'scope': claims['scp'], 'claims': claims}, cookie)
            else:
                authorization = self.headers.get('Authorization', '')
                if not authorization.startswith('Bearer '):
                    result = box.gateway.call('', None, {})
                    self._json(401 if result.reason != 'audit_failure' else 503, {'error': result.reason}, cookie)
                    return
                self._json(200, box.gateway.mcp(payload, authorization[7:]), cookie)
            return
        if self.headers.get_content_type() != 'application/x-www-form-urlencoded':
            self._send(415, layout('Unsupported media type', '<p>Expected a form body.</p>'), cookie=cookie)
            return
        form = self._form(body)
        if not self._csrf_ok(box, form):
            self._send(403, layout('Forbidden', '<p>CSRF validation failed.</p>'), cookie=cookie)
            return
        message = '<p>Done.</p>'
        if path == '/agents':
            box.admit('registrations', 10)
            agent, secret = box.registry.register(form.get('name', ''))
            box.pending_secrets[agent.agent_id] = secret
            if box._test_secrets is not None:
                box._test_secrets[agent.agent_id] = secret
            box.audit.append('agent.register', agent.agent_id, reason='created')
            message = '<p>Agent created. Open Agents to reveal its secret once.</p>'
        elif path == '/agents/revoke':
            box.registry.revoke(form.get('agent_id', ''))
            message = '<p>Agent revoked.</p>'
        elif path == '/token':
            box.admit('tokens', 10)
            agent_id = form.get('agent_id', '')
            secret = form.get('client_secret', '')
            if self.server.state.test_mode and not secret:
                secret = box.secrets.get(agent_id, '')
            try:
                token, claims = box.gateway.issue_token(agent_id, secret, [item.strip() for item in form.get('scopes', '').split(',') if item.strip()])
            except AuthError:
                self._send(401, layout('Token', '<p class=bad>Invalid client credentials.</p>' + self._token_form(box)), cookie=cookie)
                return
            except TokenError:
                self._send(400, layout('Token', '<p class=bad>Select at least one permitted scope.</p>' + self._token_form(box)), cookie=cookie)
                return
            box.last_tokens[agent_id] = token
            expiry = datetime.datetime.fromtimestamp(claims['exp'], datetime.UTC).isoformat()
            message = '<h2>Bearer token</h2><pre>' + esc(token) + '</pre><h2>Decoded claims</h2><pre>' + esc(json.dumps(claims, indent=2)) + '</pre><p>Expires: ' + esc(expiry) + ' (UTC); lifetime ' + str(claims['exp'] - claims['iat']) + ' seconds.</p>' + self._token_form(box)
        elif path == '/token/revoke':
            box.tokens.revoke(box.last_tokens.get(form.get('agent_id', ''), ''))
            message = '<p>Saved token revoked.</p>'
        elif path == '/keys/rotate':
            box.keys.rotate()
            message = '<p>Signing key rotated. Only the newest three keys are retained; tokens signed by a retired key no longer work.</p>'
        elif path == '/call':
            token = form.get('token') or box.last_tokens.get(form.get('agent_id', ''), '')
            result = box.gateway.call(token, form.get('tool', ''), self._arguments(form.get('arguments', '')))
            message = self._call_form(box, '<p class="' + ('ok' if result.allowed else 'bad') + '">' + esc(result.reason) + '</p><pre>' + esc(json.dumps(result.result, indent=2)) + '</pre>')
        elif path == '/policy':
            box.policy.load(form.get('policy', ''))
            message = '<p class=ok>Policy loaded.</p>'
        elif path == '/audit/verify':
            box.admit('audit_verify', 5)
            valid, index = box.audit.verify()
            message = '<p>' + ('✓ audit chain valid' if valid else '✗ chain broken at index ' + str(index)) + '</p>'
        elif path == '/audit/tamper' and self.server.state.demo_tamper:
            box.audit._tamper_for_demo(int(form.get('index', '-1')))
            message = '<p>Demo entry changed.</p>'
        else:
            self._send(404, layout('Not found', '<p>The requested page does not exist.</p>'), cookie=cookie)
            return
        self._send(200, layout(path.strip('/').title(), message), cookie=cookie)


def _public_origin(value):
    if value is None or value == '':
        return None
    if not isinstance(value, str) or len(value) > 2048 or any(ord(char) < 32 for char in value):
        raise ValueError('invalid PUBLIC_BASE_URL')
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError('invalid PUBLIC_BASE_URL') from exc
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ValueError('PUBLIC_BASE_URL must be an HTTPS origin')
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('invalid PUBLIC_BASE_URL')
    return 'https://' + parsed.netloc.lower()


def make_server(address=('127.0.0.1', 8080), secure_cookies=False, demo_tamper=True, *, test_mode=False, clock=None, max_workers=16, request_timeout=3, public_base_url=None, allowed_hosts=()):
    public_base_url = _public_origin(public_base_url)
    allowed = {str(host).strip().lower() for host in allowed_hosts if str(host).strip()}
    if public_base_url:
        allowed.add(urlsplit(public_base_url).netloc.lower())
        secure_cookies = True
    server = BoundedHTTPServer(address, Handler, max_workers, request_timeout)
    server.state = DemoState(test_mode=test_mode, demo_tamper=demo_tamper, clock=clock)
    server.secure_cookies = secure_cookies
    server.public_base_url = public_base_url
    server.allowed_hosts = frozenset(allowed)
    return server


def listen_address_from_env(environ=None):
    environ = os.environ if environ is None else environ
    host = environ.get('DEMO_HOST', environ.get('HOST', '127.0.0.1'))
    if not isinstance(host, str) or not host or len(host) > 253 or any(char.isspace() or ord(char) < 32 for char in host):
        raise ValueError('invalid DEMO_HOST')
    port = int(environ.get('PORT', '8080'))
    if not 0 <= port <= 65535:
        raise ValueError('invalid PORT')
    return host, port


def server_options_from_env(environ=None):
    environ = os.environ if environ is None else environ
    address = listen_address_from_env(environ)
    public_base_url = _public_origin(environ.get('PUBLIC_BASE_URL'))
    platform_tls = environ.get('DEMO_HTTPS_TERMINATED', '').lower() == 'true'
    legacy_tls = environ.get('AGENTGATE_TLS') == '1'
    secure_cookies = bool(public_base_url) or platform_tls or legacy_tls
    try:
        loopback = ipaddress.ip_address(address[0]).is_loopback
    except ValueError:
        loopback = False
    if not loopback and not (platform_tls or legacy_tls):
        raise ValueError('non-loopback DEMO_HOST requires DEMO_HTTPS_TERMINATED=true or AGENTGATE_TLS=1 and an HTTPS reverse proxy')
    return {
        'address': address,
        'secure_cookies': secure_cookies,
        'demo_tamper': environ.get('AGENTGATE_DEMO_TAMPER', '1') == '1',
        'public_base_url': public_base_url,
    }


def main():
    options = server_options_from_env()
    host, _ = options['address']
    server = make_server(**options)
    shown_host = '[' + host + ']' if ':' in host else host
    print(f'AgentGate demo listening on http://{shown_host}:{server.server_port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
