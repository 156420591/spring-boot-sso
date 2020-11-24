from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, url_for
from flask.json import jsonify
import os, sys

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)


client_id = "foo"
client_secret = "bar"
authorization_base_url = 'http://localhost:8080/sso-server/oauth/authorize'
token_url = 'http://localhost:8080/sso-server/oauth/token'
redirect_uri = 'http://localhost:8083/login'
state = ''

@app.route("/apple/hello", methods=["GET"])
def apple_hello():
    if 'oauth_token' not in session:
        return redirect('/')
    return "apple_hello"
    
@app.route("/pear/hello", methods=["GET"])
def pear_hello():
    if 'oauth_token' not in session:
        return redirect('/')
    return "pear_hello"

@app.route("/")
def demo():

    github = OAuth2Session(client_id, redirect_uri=redirect_uri)
    authorization_url, state = github.authorization_url(authorization_base_url)

    session['oauth_state'] = state
    return redirect(authorization_url)



@app.route("/login", methods=["GET"])
def login():

    github = OAuth2Session(client_id, state=session['oauth_state'], redirect_uri=redirect_uri)
    token = github.fetch_token(token_url, client_secret=client_secret, authorization_response=request.url)

    session['oauth_token'] = token
    print '=================token:', token
    sys.stdout.flush()
    userinfo = github.get('http://localhost:8080/sso-server/user/me')
    print '=================userinfo:', userinfo.content
    sys.stdout.flush()

    return redirect(url_for('.profile'))


@app.route("/profile", methods=["GET"])
def profile():
    """Fetching a protected resource using an OAuth 2 token.
    """
    github = OAuth2Session(client_id, token=session['oauth_token'])
    return "hello, in python"


if __name__ == "__main__":
    os.environ['DEBUG'] = "1"

    app.secret_key = os.urandom(24)
    app.run(debug=True, host = "localhost", port = 8083)