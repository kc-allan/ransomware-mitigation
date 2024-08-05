import flask
import flask_login
from app.models.user import User
from app import db

from . import auth


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'POST':
        user = User.query.filter_by(email=flask.request.form['email']).first()
        if user and user.verify_password(flask.request.form['password']):
            flask_login.login_user(user)
            flask.flash('Logged in successfully.', 'green')
            return flask.redirect(flask.url_for('main.index'))
        flask.flash('Invalid username or password', 'red')
    return flask.render_template('auth/login.html', title='Sign In', current_user=flask_login.current_user)


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if flask.request.method == 'POST':
        user = User(
            email=flask.request.form['email'],
            password=flask.request.form['password']
        )
        db.session.add(user)
        db.session.commit()
        flask_login.login_user(user)
        flask.flash('Account created successfully.', 'green')
        return flask.redirect(flask.url_for('accounts.dashboard'))
    return flask.render_template('auth/register.html', title='Register', current_user=flask_login.current_user)
