from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField


class LoginForm(FlaskForm):
    username = StringField('Username')
    password = StringField('Password')
    submit = SubmitField('Submit')


class RegistrationForm(FlaskForm):
    username = StringField('Username')
    password = StringField('Password')
    submit = SubmitField('Submit')
