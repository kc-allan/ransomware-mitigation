import flask
import flask_login
from flask_login import current_user

from app.routes.main import main


@main.route('/')
def index():
    return flask.redirect('/auth/login')
