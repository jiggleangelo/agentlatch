import http.client
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path


class HostingContractTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]
    PUBLIC_HOST = 'try-agentlatch.manykiln.com'
    PUBLIC_BASE_URL = 'https://' + PUBLIC_HOST

    @staticmethod
    def available_port():
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            return listener.getsockname()[1]

    def test_contract_environment_starts_and_accepts_public_host(self):
        port = self.available_port()
        env = os.environ.copy()
        env.update({
            'DEMO_HOST': '127.0.0.1',
            'PORT': str(port),
            'PUBLIC_BASE_URL': self.PUBLIC_BASE_URL,
            'DEMO_HTTPS_TERMINATED': 'true',
        })
        process = subprocess.Popen(
            [sys.executable, 'demo.py'],
            cwd=self.ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 10
            last_error = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    stdout, stderr = process.communicate(timeout=1)
                    self.fail(f'demo exited early with {process.returncode}: {stdout}{stderr}')
                try:
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
                    connection.request('GET', '/healthz', headers={'Host': self.PUBLIC_HOST})
                    response = connection.getresponse()
                    body = response.read()
                    connection.close()
                    self.assertEqual((response.status, body), (200, b'ok'))
                    break
                except OSError as exc:
                    last_error = exc
                    time.sleep(0.05)
            else:
                self.fail(f'demo did not become ready: {last_error}')

            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
            connection.request('GET', '/', headers={'Host': self.PUBLIC_HOST})
            response = connection.getresponse()
            page = response.read().decode()
            cookie = response.getheader('Set-Cookie')
            connection.close()
            self.assertEqual(response.status, 200)
            self.assertIn('Secure', cookie.split('; '))
            self.assertIn(self.PUBLIC_BASE_URL + '/agents', page)

            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
            connection.request('GET', '/healthz', headers={'Host': 'untrusted.example'})
            response = connection.getresponse()
            response.read()
            connection.close()
            self.assertEqual(response.status, 421)
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def test_default_bind_remains_loopback(self):
        import demo
        self.assertEqual(demo.listen_address_from_env({}), ('127.0.0.1', 8080))


if __name__ == '__main__':
    unittest.main()
