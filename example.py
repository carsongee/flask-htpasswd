import flask
from flask.ext.htpasswd import HtPasswdAuth

app = flask.Flask(__name__)
app.config['FLASK_HTPASSWD_PATH'] = '/Users/cgee/tmp/.htpasswd'
app.config['FLASK_SECRET'] = 'Hey Hey Kids'
htpasswd = HtPasswdAuth(app)


@app.route('/')
@htpasswd.required
def index(user):
    return flask.jsonify({'token': htpasswd.generate_token(user)})

app.run(debug=True)
