"""
Test module for Flask-htpasswd extension
"""
from __future__ import absolute_import, unicode_literals
import base64
import os
import unittest

from flask import request, Flask, g
from itsdangerous import JSONWebSignatureSerializer as Serializer
import mock

from flask_htpasswd import HtPasswdAuth


class TestAuth(unittest.TestCase):
    """
    Verify each piece of our authentication module using
    the htpasswd in tests/config/
    """
    TEST_USER = 'foo'
    TEST_PASS = 'bar'
    NOT_USER = 'notuser'

    def setUp(self):
        super(TestAuth, self).setUp()
        self.app = Flask(__name__)
        self.app.config['FLASK_SECRET'] = 'dummy'
        self.app.debug = True
        self.htpasswd = None

    def _setup_normal_extension(self, auth_all=False, realm=None):
        """Setup the extension with the test htpasswd file."""
        self.app.config['FLASK_HTPASSWD_PATH'] = os.path.join(
            os.path.dirname(
                os.path.abspath(__file__)
            ),
            'config',
            'test_htpasswd'
        )
        if auth_all:
            self.app.config['FLASK_AUTH_ALL'] = True
        if realm:
            self.app.config['FLASK_AUTH_REALM'] = realm
        self.htpasswd = HtPasswdAuth(self.app)

    def _get_requires_auth_decorator(self):
        """
        Returns decorated mock function.
        """
        wrapped = mock.Mock()
        wrapped.__name__ = str('foo')
        decorated = self.htpasswd.required(wrapped)
        return wrapped, decorated

    def test_app_factory(self):
        """Verify we work fine even without an app in __init__"""
        htpasswd = HtPasswdAuth()
        htpasswd.init_app(self.app)

    @mock.patch('flask_htpasswd.log')
    def test_no_htpasswd_file(self, mocked_log):
        """Verify that we are just fine without an htpasswd file"""
        HtPasswdAuth(self.app)
        mocked_log.critical.assert_called_with(
            'No htpasswd file loaded, please set `FLASK_HTPASSWD`'
            'or `FLASK_HTPASSWD_PATH` environment variable to a '
            'valid apache htpasswd file.'
        )

    def test_check_basic_auth(self):
        """
        Validate a test user works with the correct password
        and doesn't with a bad one
        """
        self._setup_normal_extension()
        with self.app.app_context():
            self.assertTrue(self.TEST_USER in self.htpasswd.users.users())
            # Verify positive case
            valid, username = self.htpasswd.check_basic_auth(
                self.TEST_USER, self.TEST_PASS
            )
            self.assertTrue(valid)
            self.assertEqual(username, self.TEST_USER)

            # Verify negative password case
            valid, username = self.htpasswd.check_basic_auth(
                self.TEST_USER, 'blah'
            )
            self.assertFalse(valid)
            self.assertEqual(self.TEST_USER, username)

            # Verify negative user case
            not_user = self.NOT_USER
            self.assertTrue(not_user not in self.htpasswd.users.users())
            valid, username = self.htpasswd.check_basic_auth(not_user, 'blah')
            self.assertFalse(valid)
            self.assertEqual(not_user, username)

    def test_token_generation(self):
        """
        Verify token generation using known hashes and signature
        """
        test_user = self.TEST_USER
        not_user = self.NOT_USER
        known_hashhash = ('5106273f7789f1e26b4a212789992f75c15433f402f3e94a'
                          'd18e7c80aee80faf')
        self._setup_normal_extension()

        with self.app.app_context():

            token = self.htpasswd.generate_token(test_user)

            # Verify hashhash against known value
            hashhash = self.htpasswd.get_hashhash(test_user)
            self.assertEqual(hashhash, known_hashhash)

            # Now that we verified our hashhash, independently verify
            # the data with a serializer from config (not trusting
            # get_signature here).
            serializer = Serializer(self.app.config['FLASK_SECRET'])
            self.assertEqual(serializer.loads(token)['hashhash'], hashhash)

            # Now go ahead and verify the reverse, trusting, and
            # verifying get_signature.
            serializer = self.htpasswd.get_signature()
            data = serializer.loads(token)
            self.assertTrue(data['username'], test_user)
            self.assertTrue(data['hashhash'], hashhash)

            # Verify no user handling (don't really care what
            # exception gets raised).
            with self.assertRaises(Exception):
                token = self.htpasswd.generate_token(not_user)

    @mock.patch('flask_htpasswd.log')
    def test_token_auth(self, log):
        """
        Validate authentication by token works properly
        """
        self._setup_normal_extension()
        with self.app.app_context():
            # Test bad token
            valid, username = self.htpasswd.check_token_auth(
                'asdfasdf.asdfasdf'
            )
            self.assertEqual(False, valid)
            self.assertEqual(None, username)
            log.warning.assert_called_with('Received bad token signature')

            # Test bad username, but valid signature for users that have
            # been deleted
            sig = self.htpasswd.get_signature()
            token = sig.dumps({
                'username': self.NOT_USER,
            })
            valid, username = self.htpasswd.check_token_auth(token)
            self.assertEqual(False, valid)
            self.assertEqual(None, username)
            log.warning.assert_called_with(
                'Token auth signed message, but invalid user %s',
                self.NOT_USER
            )

            # Test that a different password invalidates token
            token = sig.dumps({
                'username': self.TEST_USER,
                'hashhash': self.htpasswd.get_hashhash('norm')
            })
            valid, username = self.htpasswd.check_token_auth(token)
            self.assertEqual(False, valid)
            self.assertEqual(None, username)
            log.warning.assert_called_with(
                'Token and password do not match, '
                '%s needs to regenerate token',
                self.TEST_USER
            )

            # Test valid case
            token = self.htpasswd.generate_token(self.TEST_USER)
            valid, username = self.htpasswd.check_token_auth(token)
            self.assertEqual(True, valid)
            self.assertEqual(self.TEST_USER, username)

    def test_requires_auth(self):
        """
        Verify full auth with both token and basic auth.
        """
        self._setup_normal_extension()
        # Test successful basic auth
        with self.app.test_request_context(headers={
                'Authorization': 'Basic {0}'.format(
                    base64.b64encode(
                        '{0}:{1}'.format(
                            self.TEST_USER, self.TEST_PASS
                        ).encode('ascii')
                    ).decode('ascii')
                )
        }):
            wrapped, decorated = self._get_requires_auth_decorator()
            decorated()
            wrapped.assert_called_with(user=self.TEST_USER)

        # Test successful token header auth
        with self.app.app_context():
            with self.app.test_request_context(headers={
                    'Authorization': 'token {0}'.format(
                        self.htpasswd.generate_token(self.TEST_USER)
                    )
            }):
                wrapped, decorated = self._get_requires_auth_decorator()
                decorated()
                wrapped.assert_called_with(user=self.TEST_USER)

        # Test successful token param auth
        with self.app.app_context():
            with self.app.test_request_context():
                wrapped = mock.Mock()
                request.args = {
                    'access_token': self.htpasswd.generate_token(
                        self.TEST_USER
                    )
                }
                wrapped, decorated = self._get_requires_auth_decorator()
                decorated()
                wrapped.assert_called_with(user=self.TEST_USER)

        # Test unsuccessful auth
        with self.app.test_request_context(headers={
                'Authorization': 'token blah blah'
        }):
            wrapped, decorated = self._get_requires_auth_decorator()
            response = decorated()
            self.assertEqual(401, response.status_code)

    def test_auth_all_views_disabled(self):
        """Verify that with ``FLASK_AUTH_ALL`` turned off, views are normal"""
        self._setup_normal_extension()

        @self.app.route('/')
        def _():
            """Simple view to verify we aren't protected."""
            return 'Hi'

        response = self.app.test_client().get('/')
        self.assertEqual(200, response.status_code)
        self.assertEqual('Hi', response.data.decode('UTF-8'))

    def test_auth_all_views_enabled(self):
        """Verify that with ``FLASK_AUTH_ALL`` turned on, views need auth"""
        self._setup_normal_extension(auth_all=True)

        @self.app.route('/')
        def _():
            """Simple view to verify we are protected."""
            # Validate we have the user available in g
            self.assertEqual(g.user, self.TEST_USER)
            return 'Hi'

        response = self.app.test_client().get('/')
        self.assertEqual(401, response.status_code)

        # Make sure we can properly authenticate as well
        response = self.app.test_client().get(
            '/',
            headers={
                'Authorization': 'Basic {0}'.format(
                    base64.b64encode(
                        '{0}:{1}'.format(
                            self.TEST_USER, self.TEST_PASS
                        ).encode('ascii')
                    ).decode('ascii')
                )
            }
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual('Hi', response.data.decode('UTF-8'))

    def test_basic_auth_realm_config(self):
        """Verify that the auth realm returned is configurable"""
        realm = 'Foomanchubars'
        self._setup_normal_extension(auth_all=True, realm=realm)

        @self.app.route('/')
        def _():
            """Simple view to prompt for authentication."""
            self.fail(
                'This view should not have been called'
            )  # pragma: no cover

        response = self.app.test_client().get('/')
        self.assertEqual(401, response.status_code)
        self.assertEqual(
            'Basic realm="{0}"'.format(realm),
            response.headers['WWW-Authenticate']
        )

    def test_decorator_syntax(self):
        """Verify that the auth realm returned is configurable"""
        self._setup_normal_extension()

        @self.app.route('/')
        @self.htpasswd.required
        def _():
            """Simple view to validate authentication."""
            self.fail(
                'This view should not have been called'
            )  # pragma: no cover
        response = self.app.test_client().get('/')
        self.assertEqual(401, response.status_code)
