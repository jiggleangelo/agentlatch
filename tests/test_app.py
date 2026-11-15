import http.client
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

import app


class AppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.host = 'app-agentlatch.manykiln.com'
        self.origin = 'https://' + self.host
        self.server = app.make_server(('127.0.0.1', 0), self.temp.name, self.origin)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(3); self.temp.cleanup()

    def request(self, method, path, values=None, headers=None):
        headers = {'Host': self.host, **(headers or {})}
        body = None
        if values is not None:
            body = urlencode(values)
            headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
            headers.setdefault('Origin', self.origin)
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        connection.request(method, path, body, headers)
        response = connection.getresponse(); data = response.read().decode(); result = response.status, data, dict(response.getheaders()); connection.close(); return result

    def workspace(self, sample='0'):
        status, _, headers = self.request('POST', '/new', {'sample': sample})
        self.assertEqual(status, 303)
        return headers['Location'].split('/')[2]

    def test_create_notice_health_export_delete(self):
        self.assertEqual(self.request('GET', '/healthz')[:2], (200, 'ok'))
        token = self.workspace()
        status, page, _ = self.request('GET', '/w/' + token)
        self.assertEqual(status, 200); self.assertIn('only key and cannot be recovered', page); self.assertIn('real API keys, passwords or tokens', page); self.assertIn('manykiln.com/privacy', page)
        self.assertNotIn(token, ''.join(str(path) + path.read_text(errors='ignore') for path in Path(self.temp.name).rglob('*') if path.is_file()))
        status, exported, _ = self.request('GET', f'/w/{token}/export'); self.assertEqual(status, 200); self.assertIn('versions', json.loads(exported)['policy'])
        self.assertEqual(self.request('POST', f'/w/{token}/delete', {'confirm': 'DELETE'})[0], 303)
        self.assertEqual(self.request('GET', f'/w/{token}')[0], 404)

    def test_core_flow_and_security_headers(self):
        token = self.workspace('1'); base = '/w/' + token
        status, page, headers = self.request('POST', base + '/check', {'agent':'invoice-bot','tool':'payments.refund','arguments':'amount=40\ncurrency=EUR\norder_id=O'})
        self.assertEqual(status, 200); self.assertIn('allow', page); self.assertIn('same-origin', headers['Referrer-Policy'])
        _, page, _ = self.request('POST', base + '/check', {'agent':'invoice-bot','tool':'payments.refund','arguments':'amount=400\ncurrency=EUR\norder_id=O'})
        self.assertIn('constraint_failed:amount.max', page)
        secret = 'sk-live_this-value-must-never-be-written'
        _, page, _ = self.request('POST', base + '/check', {'agent':'invoice-bot','tool':'payments.refund','arguments':json.dumps({'amount':secret})})
        self.assertIn('secret_in_args', page)
        disk = ''.join(path.read_text(errors='ignore') for path in Path(self.temp.name).rglob('*') if path.is_file())
        self.assertNotIn(secret, disk)
        self.assertEqual(self.request('GET','/',headers={'Host':'wrong.example'})[0],421)
        self.assertEqual(self.request('POST','/new',{'sample':'0'},headers={'Origin':'https://evil.example'})[0],403)
        self.assertEqual(self.request('POST','/new',{'sample':'0'},headers={'Origin':'null'})[0],403)
        self.assertEqual(self.request('POST','/new',{'sample':'0'},headers={'Origin':'', 'Referer':self.origin+'/'})[0],403)

    def test_share_verify_and_persistence(self):
        token=self.workspace('1'); base='/w/'+token
        self.request('POST',base+'/check',{'agent':'invoice-bot','tool':'payments.refund','arguments':'amount=40\ncurrency=EUR\norder_id=O'})
        self.assertIn('✓',self.request('POST',base+'/log/verify',{})[1])
        page=self.request('POST',base+'/share',{'mode':'create'})[1]
        share=page.split('/s/')[1].split('&')[0].split('<')[0]
        shared=self.request('GET','/s/'+share)[1]; self.assertNotIn('<form',shared)
        self.request('POST',base+'/share',{'mode':'revoke'}); self.assertEqual(self.request('GET','/s/'+share)[0],404)
        port=self.server.server_port; self.server.shutdown(); self.server.server_close(); self.thread.join(3)
        self.server=app.make_server(('127.0.0.1',port),self.temp.name,self.origin); self.thread=threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        self.assertIn('8 saved cases',self.request('GET',base)[1])

if __name__ == '__main__': unittest.main()
