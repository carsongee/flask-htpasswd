#!/usr/bin/env python
"""
Decorator, configuration, and error handler for basic and token
authentication using htpasswd files
"""
from functools import wraps
import hashlib
import logging

from flask import request, Response, current_app
from itsdangerous import JSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature
from passlib.apache import HtpasswdFile


log = logging.getLogger(__name__)  # pylint: disable=invalid-name


class HtPasswdAuth(object):
    """Configure htpasswd based basic and token authentication."""

    def __init__(self, app=None):
        """Boiler plate extension init with log_level being declared"""
        self.users = HtpasswdFile()
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Find and configure the user database from specified file
        """
        app.config.setdefault('FLASK_AUTH_ALL', False)
        app.config.setdefault('FLASK_AUTH_REALM', 'Login Required')
        # Default set to bad file to trigger IOError
        app.config.setdefault('FLASK_HTPASSWD_PATH', '/^^^/^^^')

        # Load up user database
        try:
            users = HtpasswdFile(
                app.config['FLASK_HTPASSWD_PATH']
            )
            self.users = users
        except IOError:
            log.critical(
                'No htpasswd file loaded, please set `FLASK_HTPASSWD`'
                'or `FLASK_HTPASSWD_PATH` environment variable to a '
                'valid apache htpasswd file.'
            )

        # Allow requiring auth for entire app, with pre request method
        @app.before_request
        def require_auth():  # pylint: disable=unused-variable
            """Pre request processing for enabling full app authentication."""
            if not current_app.config['FLASK_AUTH_ALL']:
                return
            is_valid, _ = self.authenticate()
            if not is_valid:
                return self.auth_failed()

    def check_basic_auth(self, username, password):
        """
        This function is called to check if a username /
        password combination is valid via the htpasswd file.
        """
        valid = self.users.check_password(
            username, password
        )
        if not valid:
            log.warn('Invalid login from %s', username)
            valid = False
        return (
            valid,
            username
        )

    @staticmethod
    def get_signature():
        """
        Setup crypto sig.
        """
        return Serializer(current_app.config['FLASK_SECRET'])

    def get_hashhash(self, username):
        """
        Generate a digest of the htpasswd hash
        """
        return hashlib.sha256(
            self.users.find(username)
        ).hexdigest()

    def generate_token(self, username):
        """
        assumes user exists in htpasswd file.

        Return the token for the given user by signing a token of
        the username and a hash of the htpasswd string.
        """
        serializer = self.get_signature()
        return serializer.dumps(
            {
                'username': username,
                'hashhash': self.get_hashhash(username)
            }
        )

    def check_token_auth(self, token):
        """
        Check to see who this is and if their token gets
        them into the system.
        """
        serializer = self.get_signature()

        try:
            data = serializer.loads(token)
        except BadSignature:
            log.warn('Received bad token signature')
            return False, None
        if data['username'] not in self.users.users():
            log.warn(
                'Token auth signed message, but invalid user %s',
                data['username']
            )
            return False, None
        if data['hashhash'] != self.get_hashhash(data['username']):
            log.warn(
                'Token and password do not match, %s '
                'needs to regenerate token',
                data['username']
            )
            return False, None
        return True, data['username']

    @staticmethod
    def auth_failed():
        """
        Sends a 401 response that enables basic auth
        """
        return Response(
            'Could not verify your access level for that URL.\n'
            'You have to login with proper credentials',
            401,
            {'WWW-Authenticate': 'Basic realm="{0}"'.format(
                current_app.config['FLASK_AUTH_REALM']
            )}
        )

    def authenticate(self):
        """Authenticate user by any means and return either true or false.

        Args:

        Returns:
            tuple (is_valid, username): True is valid user, False if not
        """
        basic_auth = request.authorization
        is_valid = False
        user = None
        if basic_auth:
            is_valid, user = self.check_basic_auth(
                basic_auth.username, basic_auth.password
            )
        else:  # Try token auth
            token = request.headers.get('Authorization', None)
            param_token = request.args.get('access_token')
            if token or param_token:
                if token:
                    # slice the 'token ' piece of the header (following
                    # github style):
                    token = token[6:]
                else:
                    # Grab it from query dict instead
                    token = param_token
                log.debug('Received token: %s', token)

                is_valid, user = self.check_token_auth(token)
        return (is_valid, user)

    def required(self, func):
        """
        Decorator function with basic and token authentication handler
        """
        @wraps(func)
        def decorated(*args, **kwargs):
            """
            Actual wrapper to run the auth checks.
            """
            is_valid, user = self.authenticate()
            if not is_valid:
                return self.auth_failed()
            kwargs['user'] = user
            return func(*args, **kwargs)
        return decorated
