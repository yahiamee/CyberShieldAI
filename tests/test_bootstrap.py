import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch
from pathlib import Path

from database import init_db, verify_password


class AdministratorBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.previous = Path.cwd()
        os.chdir(self.directory.name)
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        os.chdir(self.previous)
        self.directory.cleanup()

    def users(self):
        with closing(sqlite3.connect('cybershield.db')) as connection:
            return connection.execute('SELECT username, password_hash, is_admin FROM users').fetchall()

    def test_no_default_admin_is_created(self):
        init_db()
        self.assertEqual(self.users(), [])

    def test_configured_admin_is_hashed_and_not_overwritten(self):
        os.environ['CYBERSHIELD_ADMIN_PASSWORD'] = 'unique-test-password-123'
        init_db()
        original = self.users()
        self.assertEqual(original[0][0], 'admin')
        self.assertTrue(verify_password('admin', 'unique-test-password-123'))
        os.environ['CYBERSHIELD_ADMIN_PASSWORD'] = 'different-test-password-456'
        init_db()
        self.assertEqual(self.users(), original)

    def test_short_bootstrap_password_is_rejected(self):
        os.environ['CYBERSHIELD_ADMIN_PASSWORD'] = 'short'
        with self.assertRaises(ValueError):
            init_db()


if __name__ == '__main__':
    unittest.main()
