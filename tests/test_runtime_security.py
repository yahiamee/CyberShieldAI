import importlib.util
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import requests


SOURCE = Path(__file__).resolve().parents[1] / 'app.py'


def load_application():
    spec = importlib.util.spec_from_file_location('cybershield_test_app', SOURCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.app


class RuntimeSecurityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.previous = Path.cwd()
        os.chdir(self.directory.name)
        self.environment = patch.dict(os.environ, {
            'SECRET_KEY': 'test-session-key-that-exceeds-thirty-two-characters',
            'CYBERSHIELD_ADMIN_PASSWORD': 'unique-test-administrator-password',
        }, clear=True)
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        os.chdir(self.previous)
        self.directory.cleanup()

    def test_openai_client_initializes_without_network(self):
        from openai import OpenAI
        client = OpenAI(api_key='test-not-a-real-key')
        client.close()

    def test_missing_session_key_prevents_startup(self):
        os.environ.pop('SECRET_KEY')
        with self.assertRaisesRegex(RuntimeError, 'SECRET_KEY'):
            load_application()

    def test_tls_failure_is_not_retried_without_verification(self):
        with patch('zap_manager.init_zap', return_value=None):
            app = load_application()
        app.config['TESTING'] = True
        client = app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = '1'
            session['_fresh'] = True
        with patch('requests.get', side_effect=requests.exceptions.SSLError('certificate failure')) as get:
            response = client.post('/scan', data={'url': 'https://example.com', 'scan_type': 'basic'})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'TLS certificate verification failed', response.data)
        get.assert_called_once()
        self.assertIs(get.call_args.kwargs['verify'], True)


if __name__ == '__main__':
    unittest.main()
