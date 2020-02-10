Flask-htpasswd
--------------
.. image:: https://img.shields.io/travis/carsongee/flask-htpasswd.svg
    :target: https://travis-ci.org/carsongee/flask-htpasswd
.. image:: https://img.shields.io/coveralls/carsongee/flask-htpasswd.svg
    :target: https://coveralls.io/r/carsongee/flask-htpasswd
.. image:: https://img.shields.io/github/issues/carsongee/flask-htpasswd.svg
    :target: https://github.com/carsongee/flask-htpasswd/issues
.. image:: https://img.shields.io/pypi/dm/flask-htpasswd.svg
    :target: https://pypi.python.org/pypi/flask-htpasswd/
.. image:: https://img.shields.io/pypi/v/flask-htpasswd.svg
    :target: https://pypi.python.org/pypi/flask-htpasswd/
.. image:: https://img.shields.io/badge/license-BSD-blue.svg
    :target: https://github.com/carsongee/flask-htpasswd/blob/master/LICENSE


Flask extension for providing basic digest and token authentication
via apache htpasswd files.  So largely it fits between `Flask-Security
<https://pythonhosted.org/Flask-Security/>`_ which has additional
dependencies and `Flask-BasicAuth
<http://flask-basicauth.readthedocs.org/en/latest/>`_ which only
allows you to have one user (and also puts the plain text password
into the configuration).

Sample usage is to first create an htpasswd file with the `apache tool <http://httpd.apache.org/docs/2.2/programs/htpasswd.html>`_:

.. code-block:: bash

  htpasswd -c /path/to/.htpasswd my_username

Additional users can be added, or have their passwords changed, by running:

.. code-block:: bash

  htpasswd /path/to/.htpasswd new_user
  htpasswd /path/to/.htpasswd user_I_want_to_change_passwords_for

Then you just need to setup and configure your flask application, with
something like:

.. code-block:: python

  import flask
  from flask_htpasswd import HtPasswdAuth

  app = flask.Flask(__name__)
  app.config['FLASK_HTPASSWD_PATH'] = '/path/to/.htpasswd'
  app.config['FLASK_SECRET'] = 'Hey Hey Kids, secure me!'

  htpasswd = HtPasswdAuth(app)
  

  @app.route('/')
  @htpasswd.required
  def index(user):
      return 'Hello {user}'.format(user=user)

  app.run(debug=True)

And that view should now prompt for a username and password (and
accept tokens).

If you would like to protect all of your views, that is easy too, just
add a little config. By setting ``app.config['FLASK_AUTH_ALL']=True``
before initializing the extension, an ``@app.before_request`` is added
that will require auth for all pages, and it will add the user as
``flask.g.user``.

One last small feature, is that you can also set the authentication
realm.  The default is 'Login Required', but it can be set with
``app.config['FLASK_AUTH_REALM']`` before initialization.


Using Tokens
============

Tokens are based on the username and password, and thus invalid
whenever the user's password is changed.  To get a user password, you
can serve it out to the user with something like

.. code-block:: python

  import flask
  from flask_htpasswd import HtPasswdAuth

  app = flask.Flask(__name__)
  app.config['FLASK_HTPASSWD_PATH'] = '/path/to/.htpasswd'
  app.config['FLASK_SECRET'] = 'Hey Hey Kids, secure me!'
  htpasswd = HtPasswdAuth(app)
  

  @app.route('/')
  @htpasswd.required
  def index(user):
      return flask.jsonify({'token': htpasswd.generate_token(user)})

  app.run(debug=True)

It can then be used by the user by adding it to the header of their requests, something like:

.. code-block:: python

  import requests

  requests.get('http://localhost:5000/', headers={'Authorization': 'token <token>'})


Release Notes
=============

0.3.1
`````

- Corrected deprecated passlib API call

0.3.0
`````

- Added function to reload user database
- Added user to ``flask.g`` with FLASK_AUTH_ALL=True

0.2.0
`````

- Python 3 compatability

Acknowledgements
================

This is largely based on a combination of:

- http://flask-basicauth.readthedocs.org/en/latest/
- http://flask.pocoo.org/snippets/8/
- http://blog.miguelgrinberg.com/post/restful-authentication-with-flask


Links
`````

* `documentation
  <https://github.com/carsongee/flask-htpasswd/blob/master/README.rst>`_
* `development version
  <https://github.com/carsongee/flask-htpasswd/archive/master.tar.gz#egg=flask-htpasswd-dev>`_
