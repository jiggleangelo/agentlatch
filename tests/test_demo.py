import http.client, json, threading, unittest
from urllib.parse import urlencode
import demo

class DemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=demo.make_server(('127.0.0.1',0), test_mode=True); cls.port=cls.server.server_port
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True); cls.thread.start(); cls.cookie=None
    @classmethod
    def tearDownClass(cls): cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
    def request(self,method,path,body=None,headers=None):
        headers=dict(headers or {})
        if self.cookie: headers['Cookie']=self.cookie
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=3); conn.request(method,path,body,headers); response=conn.getresponse(); data=response.read(); all_headers=dict(response.getheaders()); conn.close()
        if 'Set-Cookie' in all_headers: self.cookie=all_headers['Set-Cookie'].split(';',1)[0]
        self.assertIn("default-src 'none'",all_headers['Content-Security-Policy']); self.assertEqual(all_headers['X-Content-Type-Options'],'nosniff')
        return response.status,data,all_headers
    def form(self,path,data): return self.request('POST',path,urlencode(data),{'Content-Type':'application/x-www-form-urlencoded'})
    def test_flow(self):
        status,data,_=self.request('GET','/healthz'); self.assertEqual((status,data),(200,b'ok'))
        status,data,_=self.request('GET','/'); self.assertIn(demo.BANNER.encode(),data); self.assertIsNotNone(self.cookie)
        for path in ('/agents','/call','/policy','/audit','/partner','/cra','/missing'):
            _,data,_=self.request('GET',path); self.assertIn(demo.BANNER.encode(),data)
        box=next(iter(self.server.state.boxes.values())); agent=next(a for a in box.registry.agents.values() if a.name=='invoice-bot')
        status,data,_=self.form('/token',{'agent_id':agent.agent_id,'scopes':'crm.lookup_account,payments.refund'}); self.assertEqual(status,200); self.assertIn(b'agt1.',data)
        payload=json.dumps({'client_id':agent.agent_id,'client_secret':box.secrets[agent.agent_id],'scope':['payments.refund']})
        status,data,_=self.request('POST','/api/token',payload,{'Content-Type':'application/json'}); token=json.loads(data)['access_token']
        call={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'payments.refund','arguments':{'amount':40,'currency':'EUR','order_id':'ORD-1001'}}}
        _,data,_=self.request('POST','/api/mcp',json.dumps(call),{'Content-Type':'application/json','Authorization':'Bearer '+token}); self.assertTrue(json.loads(data)['result']['allowed'])
        call['params']['arguments']['amount']=400
        _,data,_=self.request('POST','/api/mcp',json.dumps(call),{'Content-Type':'application/json','Authorization':'Bearer '+token}); self.assertEqual(json.loads(data)['result']['reason'],'constraint_failed:amount.max')
        _,data,_=self.form('/call',{'agent_id':agent.agent_id,'tool':'email.send','arguments':'to=x@example.test\nbody=hello'}); self.assertIn(b'out_of_scope',data)
        _,data,_=self.form('/audit/verify',{}); self.assertIn('✓'.encode(),data)
        self.form('/audit/tamper',{'index':'4'}); _,data,_=self.form('/audit/verify',{}); self.assertIn(b'chain broken at index',data)
        self.form('/agents/revoke',{'agent_id':agent.agent_id}); _,data,_=self.form('/call',{'agent_id':agent.agent_id,'tool':'payments.refund','arguments':'amount=40\ncurrency=EUR\norder_id=O'}); self.assertIn(b'invalid_token',data)
    def test_limits_and_escape(self):
        status,_,_=self.request('POST','/agents',b'x'*70000,{'Content-Length':'70000'}); self.assertEqual(status,413)
        _,data,_=self.form('/agents',{'name':'<script>alert(1)</script>'}); self.assertNotIn(b'<script>',data)
if __name__ == '__main__': unittest.main()
