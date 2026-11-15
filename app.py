import html
import ipaddress
import json
import os
import secrets
import threading
import time
from contextlib import nullcontext
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from agentgate.audit import AuditLog, Entry
from agentgate.clock import FakeClock, SystemClock
from agentgate.lint import lint_policy
from agentgate.policy import PolicyError
from agentgate.sample_data import AGENTS, POLICY
from agentgate.secrets_guard import looks_like_secret, secret_paths
from agentgate.simulate import PolicyEngine, decode_json, outcome_diff, parse_arguments, parse_jsonl, run_case, run_suite
from agentgate.starter import MAX_TOOLS, generate_policy, import_catalogue
from agentgate.workspace import MissingWorkspace, StorageError, WorkspaceStore

NOTICE = "Operated by AI agents. Early version: keep your own copy of anything important. Do not enter real API keys, passwords or tokens, or other people's personal data. Nothing is charged."
CSS = 'body{font:16px system-ui;max-width:1100px;margin:auto;padding:1rem;color:#17202a}.notice{background:#fff3cd;border:1px solid #b98b00;padding:1rem}nav a{margin-right:1rem}textarea{width:100%;max-width:100%;padding:.5rem}input,button,select{padding:.45rem;margin:.2rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:.35rem;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f7;padding:1rem}.ok{color:#087830}.bad{color:#b00020}'
SAMPLE_TOOLS = [
    {'name': 'crm.lookup_account', 'description': 'Look up a made-up account', 'properties': [{'name': 'account_id', 'type': 'string', 'maxLength': 64}]},
    {'name': 'payments.refund', 'description': 'Queue a fake refund', 'properties': [{'name': 'amount', 'type': 'number', 'minimum': 0.01, 'maximum': 100}, {'name': 'currency', 'type': 'string', 'enum': ['EUR']}, {'name': 'order_id', 'type': 'string', 'maxLength': 64}]},
    {'name': 'files.read', 'description': 'Read a fake report', 'properties': [{'name': 'path', 'type': 'string', 'maxLength': 256}]},
    {'name': 'email.send', 'description': 'Demonstrates default denial', 'properties': []}]
SAMPLE_CASES = [
    {'agent': 'invoice-bot', 'tool': 'payments.refund', 'args': {'amount': 40, 'currency': 'EUR', 'order_id': 'ORD-1001'}, 'expect': 'allow', 't': 0},
    {'agent': 'invoice-bot', 'tool': 'payments.refund', 'args': {'amount': 400, 'currency': 'EUR', 'order_id': 'ORD-1002'}, 'expect': 'constraint_failed:amount.max', 't': 1},
    {'agent': 'support-triage', 'tool': 'files.read', 'args': {'path': '/srv/reports/q3.txt'}, 'expect': 'allow', 't': 2},
    {'agent': 'support-triage', 'tool': 'email.send', 'args': {}, 'expect': 'deny', 't': 3},
    {'agent': 'invoice-bot', 'tool': 'crm.lookup_account', 'args': {'account_id': 'ACME-1'}, 'expect': 'allow', 't': 4},
    {'agent': 'research-scraper', 'tool': 'files.read', 'args': {'path': '/srv/reports/public/a.txt'}, 'expect': 'allow', 't': 5},
    {'agent': 'invoice-bot', 'tool': 'payments.refund', 'args': {'amount': 10, 'currency': 'USD', 'order_id': 'O'}, 'expect': 'constraint_failed:currency.in', 't': 6},
    {'agent': 'unknown', 'tool': 'email.send', 'args': {}, 'expect': 'explicit_deny', 't': 7}]
AUDIT_LIMIT = 2000


def esc(value):
    return html.escape(str(value), quote=True)


def has_secret(value):
    """Policy identifiers are structural; constraint values remain entropy checked."""
    if not isinstance(value, dict) or not isinstance(value.get('rules'), list):
        return bool(secret_paths(value))
    for rule in value['rules']:
        for field in ('agent', 'tool', 'effect'):
            if looks_like_secret(rule.get(field), entropy=False):
                return True
        for name, operators in rule.get('constraints', {}).items():
            if looks_like_secret(name, entropy=False) or secret_paths(operators):
                return True
        for key, child in rule.items():
            if key not in ('agent', 'tool', 'effect', 'constraints', 'rate_per_minute') and secret_paths({key: child}):
                return True
    return any(secret_paths({key: child}) for key, child in value.items() if key not in ('version', 'rules'))


def withheld_copy(value):
    paths = secret_paths(value)

    def visit(child, path=()):
        if any(path[:len(item)] == item for item in paths):
            return '<withheld>'
        if isinstance(child, dict):
            return {key: visit(item, path + (str(key),)) for key, item in child.items()}
        if isinstance(child, list):
            return [visit(item, path + (str(index),)) for index, item in enumerate(child)]
        return child

    return visit(value)


def audit_from(data, tools=()):
    log = AuditLog(SystemClock(), limit=AUDIT_LIMIT, chain_key=bytes.fromhex(data['chain_key']), digest_key=bytes.fromhex(data['digest_key']), tool_names=[item['name'] for item in tools])
    log.entries = [Entry(**item) for item in data.get('entries', [])]
    log._version = len(log.entries)
    log._verify_cache_version = -1
    return log


def append_audit(state, events):
    if len(state['log']['entries']) + len(events) > AUDIT_LIMIT:
        raise StorageError('Decision log capacity reached. No changes were saved. Open Log, download and clear the log, then retry.')
    log = audit_from(state['log'], state['tools'])
    for event in events:
        log.append(**event)
    state['log']['entries'] = [asdict(item) for item in log.entries]


def save_audit(store, token, state, event, agent='workspace', tool=None, decision='n/a', reason='', args=None, withheld=()):
    with store.transaction(token):
        fresh = store.read(token)
        append_audit(fresh, [{'event': event, 'agent_id': agent, 'tool': tool, 'decision': decision, 'reason': reason, 'args': args or {}, 'withheld': withheld}])
        store.write(token, 'log', fresh['log'])


def report_events(report):
    return [{'event': 'suite.case', 'agent_id': item['agent'], 'tool': item['tool'],
             'decision': item['decision'], 'reason': item['reason'], 'args': {'case': item['case']}}
            for item in report['results']]


def findings_html(items):
    return '<ul>' + ''.join(f'<li><strong>{esc(x["id"])}</strong>: {esc(x["message"])}</li>' for x in items) + '</ul>' if items else '<p class=ok>No findings.</p>'


def result_table(report):
    if not report:
        return '<p>No suite has run.</p>'
    rows = ''.join('<tr>' + ''.join('<td>' + esc(value) + '</td>' for value in (x['case'], x['agent'], x['tool'], x['decision'], x['reason'], x['rule_index'], '—' if x['passed'] is None else ('PASS' if x['passed'] else 'FAIL'))) + '</tr>' for x in report.get('results', []))
    return f'<p>{report.get("passed", 0)} passed; {report.get("failed", 0)} failed.</p><table><tr><th>Case</th><th>Agent</th><th>Tool</th><th>Decision</th><th>Reason</th><th>Rule</th><th>Expectation</th></tr>{rows}</table>'


def public_origin(value):
    if not isinstance(value, str) or len(value) > 2048 or any(char.isspace() or ord(char) < 32 for char in value):
        raise ValueError('PUBLIC_BASE_URL must be an HTTPS origin')
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ValueError('PUBLIC_BASE_URL must be an HTTPS origin')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError('invalid PUBLIC_BASE_URL port')
    return 'https://' + parsed.netloc.lower()


def is_loopback(host):
    if host == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, handler, store, public_base_url=None, max_workers=16, request_timeout=3):
        if not public_base_url and not is_loopback(address[0]):
            raise ValueError('A non-loopback bind requires PUBLIC_BASE_URL.')
        self.store = store
        self.public_base_url = public_origin(public_base_url) if public_base_url else None
        self.slots = threading.BoundedSemaphore(max_workers)
        self.request_timeout = request_timeout
        super().__init__(address, handler)
        local_host = '[' + address[0] + ']' if ':' in address[0] else address[0]
        self.origin = self.public_base_url or f'http://{local_host}:{self.server_port}'
        self.allowed_host = urlsplit(self.origin).netloc.lower()

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(self.request_timeout)
        return sock, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            self.shutdown_request(request)

    def process_request_thread(self, *args):
        try:
            super().process_request_thread(*args)
        finally:
            self.slots.release()

    def handle_error(self, *args):
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = 'agentlatch'
    sys_version = ''

    def log_message(self, *args):
        pass

    def _layout(self, title, body, workspace=None, robots=False):
        nav = '<a href="/">Home</a>'
        if workspace:
            base = '/w/' + workspace
            nav += ''.join(f'<a href="{esc(base + path)}">{label}</a>' for path, label in (('', 'Overview'), ('/policy', 'Policy'), ('/tools', 'Tools'), ('/check', 'Check'), ('/suite', 'Suite'), ('/log', 'Log')))
        robot = '<meta name=robots content=noindex>' if robots else ''
        return f'<!doctype html><html><head><meta charset=utf-8>{robot}<meta name=viewport content="width=device-width"><title>{esc(title)}</title><style>{CSS}</style></head><body><div class=notice role=alert>{esc(NOTICE)} <a href="https://manykiln.com/privacy">Privacy</a><br>No AI model is used: decisions come from fixed rules.</div><nav>{nav}</nav><main><h1>{esc(title)}</h1>{body}</main><footer><a href="/README.md">Readiness, not compliance</a>.</footer></body></html>'

    def _send(self, status, content, kind='text/html; charset=utf-8', headers=None):
        # Emit only after the enclosing transaction commits successfully.
        if getattr(self, '_buffering', False):
            self._response = (status, content, kind, headers)
            return
        if kind.startswith('text/html') and self.server.public_base_url:
            base = esc(self.server.public_base_url)
            content = content.replace('href="/', 'href="' + base + '/').replace('action="/', 'action="' + base + '/')
        raw = content.encode()
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Connection', 'close')
        if self.path.startswith(('/w/', '/s/')):
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Robots-Tag', 'noindex, nofollow')
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.close_connection = True
        self.wfile.write(raw)

    def _error(self, status, title, message):
        token = getattr(self, '_workspace', None)
        self._send(status, self._layout(title, '<p>' + esc(message) + '</p>', token, bool(token)))

    def _host_ok(self):
        values = self.headers.get_all('Host', [])
        return len(values) == 1 and values[0].strip().lower() == self.server.allowed_host

    def _post_ok(self):
        origins = self.headers.get_all('Origin', [])
        if origins:
            return len(origins) == 1 and origins[0].lower() == self.server.origin.lower()
        referers = self.headers.get_all('Referer', [])
        if len(referers) != 1:
            return False
        parsed = urlsplit(referers[0])
        return (parsed.scheme + '://' + parsed.netloc).lower() == self.server.origin.lower()

    def _body(self):
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
            raise ValueError('One Content-Length is required.')
        size = int(self.headers['Content-Length'])
        if size < 0 or size > 1024 * 1024:
            raise OverflowError
        raw = self.rfile.read(size)
        if len(raw) != size:
            raise ValueError('Incomplete body.')
        return raw

    def _form(self, raw):
        content_type = self.headers.get_content_type()
        if content_type == 'application/x-www-form-urlencoded':
            return {key: values[-1] for key, values in parse_qs(raw.decode(), keep_blank_values=True, max_num_fields=1000).items()}
        if content_type == 'application/json':
            value = decode_json(raw)
            if not isinstance(value, dict) or any(not isinstance(item, str) for item in value.values()):
                raise ValueError('Form fields must be strings.')
            return value
        if content_type == 'multipart/form-data':
            boundary = self.headers.get_param('boundary')
            if not boundary or len(boundary) > 200:
                raise ValueError('invalid_multipart')
            out = {}
            for part in raw.split(('--' + boundary).encode())[1:-1]:
                head, sep, body = part.lstrip(b'\r\n').partition(b'\r\n\r\n')
                if not sep:
                    continue
                disposition = next((line.decode('utf-8', 'replace') for line in head.split(b'\r\n') if line.lower().startswith(b'content-disposition:')), '')
                import re
                match = re.search(r'name="([^"]+)"', disposition)
                if match:
                    out[match.group(1)] = body.removesuffix(b'\r\n').decode('utf-8')
            return out
        raise TypeError('unsupported_media_type')

    def do_GET(self):
        self._dispatch(False)

    def do_POST(self):
        self._dispatch(True)

    def _dispatch(self, post):
        self._buffering = False
        self._workspace = None
        try:
            if not self._host_ok():
                return self._error(421, 'Misdirected request', 'The Host header is not permitted.')
            if post and not self._post_ok():
                return self._error(403, 'Forbidden', 'Cross-site POST rejected.')
            path = urlsplit(self.path).path
            if path == '/healthz' and not post:
                return self._send(200, 'ok', 'text/plain; charset=utf-8')
            if path == '/README.md' and not post:
                from pathlib import Path
                return self._send(200, Path(__file__).with_name('README.md').read_text(), 'text/plain; charset=utf-8')
            form = self._form(self._body()) if post else {}
            parts = path.strip('/').split('/')
            if len(parts) >= 2 and parts[0] == 'w':
                token = parts[1]
                if len(token) != 32 or any(char not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-' for char in token):
                    raise MissingWorkspace()
                self._workspace = token
            context = self.server.store.transaction(self._workspace) if self._workspace else nullcontext()
            self._buffering = True
            with context:
                self._route(path, post, form)
            self._buffering = False
            self._send(*self._response)
        except MissingWorkspace:
            self._buffering = False
            self._error(404, 'Not found', 'Workspace not found.')
        except OverflowError:
            self._buffering = False
            self._error(413, 'Too large', 'Request body exceeds 1 MB.')
        except TypeError:
            self._buffering = False
            self._error(415, 'Unsupported media type', 'Use a form, JSON, or multipart upload.')
        except (ValueError, PolicyError, RecursionError) as exc:
            self._buffering = False
            self._error(400, 'Bad request', str(exc) or 'Invalid input.')
        except StorageError as exc:
            self._buffering = False
            self._error(429, 'Write refused', str(exc))
        except OSError:
            self.close_connection = True
        except Exception:
            self._buffering = False
            self._error(500, 'Unavailable', 'Request could not be completed.')

    def _save_policy(self, token, state, new, todos):
        PolicyEngine(FakeClock(0), new)
        if has_secret(new):
            raise ValueError('Policy rejected: secret-shaped string found.')
        diff = outcome_diff(state['policy']['current'], new, state['suite']['cases'], state['tools'])
        report = run_suite(new, state['suite']['cases'], state['tools'])
        events = [{'event': 'policy.save', 'agent_id': 'workspace', 'reason': 'saved'}] + report_events(report)
        append_audit(state, events)
        state['policy'] = {'current': new, 'versions': (state['policy'].get('versions', []) + [new])[-20:], 'todos': todos}
        state['suite']['last_report'] = report
        for name in ('policy', 'suite', 'log'):
            self.server.store.write(token, name, state[name], suite_run=name == 'suite')
        return '<p class=ok>Policy saved and suite rerun.</p><h2>Outcome diff</h2>' + ('<ul>' + ''.join(f'<li>Case {item["case"]}: {esc(item["old"])} → {esc(item["new"])}</li>' for item in diff) + '</ul>' if diff else '<p>No changed outcomes.</p>')

    def _route(self, path, post, form):
        store = self.server.store
        if path == '/' and not post:
            body = '<p>Paste a policy, import tools, dry-run calls, compare revisions, and export a tamper-evident decision record.</p><form method=post action="/new"><input type=hidden name=sample value=0><button>Start a workspace</button></form><form method=post action="/new"><input type=hidden name=sample value=1><button>Try with sample data</button></form>'
            return self._send(200, self._layout('agentlatch', body))
        if path == '/new' and post:
            seed = {'policy': POLICY, 'tools': SAMPLE_TOOLS, 'cases': SAMPLE_CASES} if form.get('sample') == '1' else None
            # Trust the TCP peer only. Forwarded headers supplied by clients are ignored.
            token = store.create(seed, source=self.client_address[0])
            return self._send(303, '', headers={'Location': '/w/' + token})
        if path.startswith('/s/') and not post:
            state = store.resolve_share(path.split('/')[2])
            findings = lint_policy(state['policy']['current'], state['tools'], state['suite']['cases'], state['suite']['last_report'], state['policy'].get('todos', []))
            return self._send(200, self._layout('Read-only review', '<h2>Policy</h2><pre>' + esc(json.dumps(state['policy']['current'], indent=2)) + '</pre><h2>Lint</h2>' + findings_html(findings) + '<h2>Last report</h2>' + result_table(state['suite']['last_report']), robots=True))
        token = self._workspace
        if not token:
            raise MissingWorkspace()
        base = '/w/' + token
        action = path[len(base):]
        state = store.read(token)
        policy = state['policy']['current']
        if action == '' and not post:
            findings = lint_policy(policy, state['tools'], state['suite']['cases'], state['suite']['last_report'], state['policy'].get('todos', []))
            valid, index = audit_from(state['log'], state['tools']).verify()
            count = len(state['log']['entries'])
            body = '<p class=bad><strong>Bookmark this link: it is the only key and cannot be recovered.</strong></p>'
            body += f'<p>{len(policy["rules"])} policy rules; {len(state["tools"])} catalogue tools; {len(state["suite"]["cases"])} saved cases.</p><h2>Lint findings</h2>' + findings_html(findings)
            body += '<h2>Last suite result</h2>' + result_table(state['suite']['last_report'])
            body += f'<p>Log: {"✓ valid" if valid else "✗ broken at index " + str(index)}; {count}/{AUDIT_LIMIT} entries. Download and clear the log before it fills; operations that cannot be logged save no changes.</p><p><a href="{base}/log">Open log</a> · <a href="{base}/export">Export everything</a> · <a href="{base}/policy.json">Download policy</a></p><form method=post action="{base}/share"><button name=mode value=create>Create read-only share link</button><button name=mode value=revoke>Revoke share link</button></form><form method=post action="{base}/delete"><label>Type DELETE <input name=confirm></label><button>Delete this workspace now</button></form><p>Exports include the audit keys for offline verification. Anyone holding those keys could also rewrite the chain.</p>'
            return self._send(200, self._layout('Workspace', body, token, True))
        if action == '/policy.json' and not post:
            return self._send(200, json.dumps(policy, indent=2), 'application/json; charset=utf-8', {'Content-Disposition': 'attachment; filename="policy.json"'})
        if action == '/export' and not post:
            return self._send(200, json.dumps(state, indent=2), 'application/json; charset=utf-8', {'Content-Disposition': 'attachment; filename="agentlatch-workspace.json"'})
        if action == '/policy':
            message, status = '', 200
            raw = json.dumps(policy, indent=2)
            versions = state['policy'].get('versions', [])
            query = parse_qs(urlsplit(self.path).query)
            if not post and 'version' in query:
                index = int(query['version'][-1])
                if not 0 <= index < len(versions):
                    raise ValueError('Unknown policy version.')
                raw = json.dumps(versions[index], indent=2)
                message = f'<p>Viewing stored version {index + 1}. Save to restore it as a new version.</p>'
            if post:
                raw = form.get('file') or form.get('policy', '')
                try:
                    if 'restore' in form:
                        index = int(form['restore'])
                        if not 0 <= index < len(versions):
                            raise ValueError('Unknown policy version.')
                        raw = json.dumps(versions[index], indent=2)
                    if len(raw.encode()) > 32768:
                        raise PolicyError('$: policy_too_large')
                    new = decode_json(raw)
                    message = self._save_policy(token, state, new, [])
                    raw = json.dumps(new, indent=2)
                    versions = state['policy']['versions']
                except (ValueError, PolicyError) as exc:
                    message, status = '<p class=bad>' + esc(str(exc)) + '</p>', 400
            history = '<h2>Stored policy versions (last 20)</h2><ul>'
            for index in range(len(versions)):
                history += f'<li><a href="{base}/policy?version={index}">View version {index + 1}</a><form method=post action="{base}/policy"><button name=restore value="{index}">Restore version {index + 1}</button></form></li>'
            history += '</ul>'
            body = message + f'<form method=post enctype=multipart/form-data action="{base}/policy"><textarea name=policy rows=24>{esc(raw)}</textarea><label>Or upload .json <input type=file name=file accept=.json></label><button>Save policy</button></form>' + history
            return self._send(status, self._layout('Policy', body, token, True))
        if action == '/tools':
            message, status = '', 200
            default_agents = '\n'.join(sorted({rule['agent'] for rule in policy['rules'] if rule['agent'] != '*'} or AGENTS))
            agents_text = form.get('agents', default_agents)
            selected_text = form.get('selected', '')
            catalogue_text = form.get('file') or form.get('catalogue', '')
            if post:
                try:
                    if form.get('mode') == 'import':
                        tools, warnings = import_catalogue(catalogue_text)
                        store.write(token, 'tools', tools)
                        state['tools'] = tools
                        message = '<p class=ok>Catalogue imported.</p>' + ''.join('<p>' + esc(item) + '</p>' for item in warnings)
                    elif form.get('mode') == 'generate':
                        agents = [item.strip() for item in agents_text.splitlines() if item.strip()]
                        selected = []
                        for line in selected_text.splitlines():
                            if line.strip():
                                agent, sep, tool = line.strip().partition('|')
                                if not sep:
                                    raise ValueError('Use one agent|tool pair per line.')
                                selected.append((agent, tool))
                                if len(selected) > 200:
                                    raise ValueError('too_many_rules: maximum 200 selected pairs')
                        generated, todos = generate_policy(state['tools'], agents, selected)
                        message = self._save_policy(token, state, generated, todos)
                    else:
                        raise ValueError('Unknown tool operation.')
                except (ValueError, PolicyError) as exc:
                    message, status = '<p class=bad>' + esc(str(exc)) + '</p>', 400
            # Never enumerate agents x tools, including for legacy catalogues.
            visible_tools = state['tools'][:MAX_TOOLS]
            if len(state['tools']) > MAX_TOOLS:
                message += '<p class=bad>Legacy catalogue exceeds 200 tools. Reimport a smaller catalogue before generation. Showing the first 200.</p>'
            body = message + f'<form method=post enctype=multipart/form-data action="{base}/tools"><input type=hidden name=mode value=import><textarea name=catalogue rows=12>{esc(catalogue_text)}</textarea><input type=file name=file accept=".json,.txt"><button>Import catalogue</button></form><p>Maximum 200 tools, 64 properties per tool, 1 MB.</p><h2>Sanitised catalogue</h2><pre>{esc(json.dumps(visible_tools, indent=2))}</pre><h2>Generate starter policy</h2><p>Enter up to 200 selected agent|tool pairs. An empty selection generates a deny-by-default policy with no allow rules.</p><form method=post action="{base}/tools"><input type=hidden name=mode value=generate><label>Agents, one per line<textarea name=agents rows=5>{esc(agents_text)}</textarea></label><label>Selected agent|tool pairs<textarea name=selected rows=10>{esc(selected_text)}</textarea></label><button>Generate starter policy</button></form>'
            return self._send(status, self._layout('Tool catalogue', body, token, True))
        if action == '/check':
            message, status = '', 200
            if post:
                try:
                    args = parse_arguments(form.get('arguments', ''))
                    case = {'agent': form.get('agent', ''), 'tool': form.get('tool', ''), 'args': args}
                    if not 1 <= len(case['agent']) <= 64 or not 1 <= len(case['tool']) <= 128:
                        raise ValueError('Agent must be 1–64 characters and tool 1–128 characters.')
                    clock = FakeClock(0)
                    result = asdict(run_case(PolicyEngine(clock, policy), case, clock, state['tools']))
                    if form.get('save') == '1' and len(state['suite']['cases']) >= 500:
                        raise ValueError('Suite already contains 500 cases.')
                    append_audit(state, [{'event': 'call.check', 'agent_id': case['agent'], 'tool': case['tool'], 'decision': result['decision'], 'reason': result['reason'], 'args': args, 'withheld': secret_paths(args)}])
                    store.write(token, 'log', state['log'])
                    message = f'<p class={"ok" if result["allowed"] else "bad"}>{esc(result["decision"])} — {esc(result["reason"])}; rule {esc(result["rule_index"])}</p>'
                    if form.get('save') == '1':
                        stored = dict(case, args=withheld_copy(args), expect=result['decision'], t=0)
                        state['suite']['cases'].append(stored)
                        state['suite']['last_report'] = None
                        store.write(token, 'suite', state['suite'])
                        message += '<p>Saved as a test case. Secret values were replaced with &lt;withheld&gt;; ordinary arguments remain in plaintext.</p>'
                except (ValueError, PolicyError) as exc:
                    message, status = '<p class=bad>' + esc(str(exc)) + '</p>', 400
            body = message + f'<form method=post action="{base}/check"><label>Agent <input name=agent required value="{esc(form.get("agent", ""))}"></label><label>Tool <input name=tool required value="{esc(form.get("tool", ""))}"></label><label>Arguments as JSON or key=value lines<textarea name=arguments rows=8>{esc(form.get("arguments", ""))}</textarea></label><button>Check</button><button name=save value=1>Check and save as test case</button></form>'
            return self._send(status, self._layout('Check one call', body, token, True))
        if action == '/suite':
            message, status = '', 200
            report = state['suite']['last_report']
            raw = form.get('file') or form.get('jsonl', '')
            if post:
                offset = int(form.get('offset', '0'))
                continuing = 'offset' in form
                checkpoint = None
                if continuing:
                    if not report or report.get('complete') or report.get('next_offset') != offset:
                        raise ValueError('This continuation is stale. Run the saved suite again.')
                    checkpoint = report.get('checkpoint')
                    if checkpoint is None:
                        raise ValueError('This older report cannot continue. Run the saved suite again.')
                elif raw.strip() or form.get('mode') == 'replace':
                    cases, errors = parse_jsonl(raw)
                    if errors:
                        message = '<h2>Parse report</h2><ul>' + ''.join(f'<li>Line {item["line"]}: {esc(item["error"])}</li>' for item in errors) + '</ul>'
                        status = 400
                    else:
                        state['suite']['cases'] = [dict(case, args=withheld_copy(case['args'])) for case in cases]
                        report = None
                if status == 200:
                    chunk = run_suite(policy, state['suite']['cases'], state['tools'], offset, 2.0, checkpoint)
                    # Audit only newly evaluated cases, before merging old results.
                    append_audit(state, report_events(chunk))
                    merged = (report.get('results', []) if continuing else []) + chunk['results']
                    report = dict(chunk, results=merged, passed=sum(item['passed'] is True for item in merged), failed=sum(item['passed'] is False for item in merged))
                    state['suite']['last_report'] = report
                    store.write(token, 'suite', state['suite'], suite_run=True)
                    store.write(token, 'log', state['log'])
            continue_form = '' if not report or report.get('complete') else f'<form method=post action="{base}/suite"><input type=hidden name=offset value="{report["next_offset"]}"><button>Continue</button></form>'
            body = message + result_table(report) + continue_form + f'<form method=post action="{base}/suite"><button>Run saved suite</button></form><h2>Replace suite</h2><p>Up to 500 JSONL cases. Non-secret arguments are stored in plaintext. Replace explicitly accepts an empty suite.</p><form method=post enctype=multipart/form-data action="{base}/suite"><textarea name=jsonl rows=16>{esc(raw)}</textarea><input type=file name=file accept=.jsonl><button name=mode value=replace>Replace and run</button></form>'
            return self._send(status, self._layout('Test suite', body, token, True))
        if action == '/log' and not post:
            query = parse_qs(urlsplit(self.path).query)
            count = len(state['log']['entries'])
            pages = max(1, (count + 49) // 50)
            page = min(pages, max(1, int(query.get('page', ['1'])[-1])))
            lines = audit_from(state['log'], state['tools']).export_jsonl((page - 1) * 50, 50)
            nav = f'<p>Page {page} of {pages}; {count}/{AUDIT_LIMIT} entries. Download and clear before the log fills. No entries are silently discarded.</p>'
            if page > 1:
                nav += f'<a href="{base}/log?page={page - 1}">Previous</a> '
            if page < pages:
                nav += f'<a href="{base}/log?page={page + 1}">Next</a>'
            body = nav + f'<pre>{esc(lines)}</pre><form method=post action="{base}/log/verify"><button>Verify</button></form><form method=post action="{base}/log/archive"><button>Download and clear log</button></form>'
            return self._send(200, self._layout('Decision log', body, token, True))
        if action == '/log/verify' and post:
            valid, index = audit_from(state['log'], state['tools']).verify()
            return self._send(200, self._layout('Verify log', '<p>' + ('✓ chain valid' if valid else '✗ chain broken at index ' + str(index)) + '</p>', token, True))
        if action == '/log/archive' and post:
            old = state['log']
            head = old['entries'][-1]['hash'] if old['entries'] else '0' * 64
            fresh = {'entries': [], 'chain_key': secrets.token_hex(32), 'digest_key': secrets.token_hex(32), 'prior_head': head}
            log = audit_from(fresh, state['tools'])
            # The public predecessor hash is HMAC-covered in the genesis reason.
            log.append('log.genesis', 'workspace', reason='prior_head:' + head)
            fresh['entries'] = [asdict(item) for item in log.entries]
            store.write(token, 'log', fresh)
            return self._send(200, json.dumps(old, indent=2), 'application/json; charset=utf-8', {'Content-Disposition': 'attachment; filename="agentlatch-log.json"'})
        if action == '/share' and post:
            if form.get('mode') == 'revoke':
                store.revoke_share(token)
                return self._send(200, self._layout('Share', '<p>Share link revoked.</p>', token, True))
            share = store.share(token)
            return self._send(200, self._layout('Share', f'<p>Read-only link: <a href="/s/{share}">/s/{share}</a></p>', token, True))
        if action == '/delete' and post:
            if form.get('confirm') != 'DELETE':
                return self._error(400, 'Confirmation required', 'Type DELETE exactly.')
            store.delete(token)
            return self._send(303, '', headers={'Location': '/'})
        raise MissingWorkspace()


def make_server(address=('127.0.0.1', 8080), data_dir=None, public_base_url=None, max_workers=16, request_timeout=3, app_data_cap_mb=200):
    if public_base_url:
        public_origin(public_base_url)
    elif not is_loopback(address[0]):
        raise ValueError('A non-loopback bind requires PUBLIC_BASE_URL.')
    store = WorkspaceStore(data_dir or os.environ.get('DATA_DIR', './data'), app_data_cap_mb)
    store.sweep()
    return Server(address, Handler, store, public_base_url, max_workers, request_timeout)


def start_sweeper(server):
    def run():
        while not getattr(server, '_agentlatch_stopped', False):
            for _ in range(8640):
                if getattr(server, '_agentlatch_stopped', False):
                    return
                time.sleep(10)
            server.store.sweep()
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def main():
    host = os.environ.get('APP_HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', '8080'))
    public = os.environ.get('PUBLIC_BASE_URL')
    if not is_loopback(host):
        if not public:
            raise ValueError('non-loopback APP_HOST requires PUBLIC_BASE_URL')
        if os.environ.get('APP_HTTPS_TERMINATED', '').lower() != 'true':
            raise ValueError('non-loopback APP_HOST requires APP_HTTPS_TERMINATED=true')
    server = make_server((host, port), os.environ.get('DATA_DIR', './data'), public, app_data_cap_mb=int(os.environ.get('APP_DATA_CAP_MB', '200')))
    start_sweeper(server)
    print(f'agentlatch listening on {host}:{server.server_port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server._agentlatch_stopped = True
        server.server_close()


if __name__ == '__main__':
    main()
