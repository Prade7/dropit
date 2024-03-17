

from flask import Flask, redirect, url_for, session,request
from flask_oauthlib.client import OAuth

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

oauth = OAuth(app)
google = oauth.remote_app(
    'google',
    consumer_key='620138119890-31gnt3h42ksvhpack9k8gtvleknv8cpe.apps.googleusercontent.com',
    consumer_secret='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',
    request_token_params={
        'scope': 'email',
    },
    base_url='https://www.googleapis.com/oauth2/v2/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

@google.tokengetter
def get_google_oauth_token():
    return session.get('access_token')


@app.route('/login')
def login():
    return google.authorize(callback=url_for('authorized', _external=True))


@app.route('/login/callback')
def authorized():
    response = google.authorized_response()
    app.logger.info(f"Google response: {response}")
    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    session['access_token'] = (response['access_token'], '')
    user_info = google.get('userinfo')
    # You can now use user_info to create or authenticate the user in your app
    return 'Logged in as: {}'.format(user_info.data['email'])

@app.route('/logout')
def logout():
    session.pop('access_token', None)
    return 'Logged out successfully!'

if __name__ == "__main__":
    app.run(debug=True)