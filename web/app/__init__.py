import flask
from flask_sse import sse
import flask_login
import flask_migrate
import flask_sqlalchemy
from config import config


login_manager = flask_login.LoginManager()
login_manager.login_view = 'auth.login'


@login_manager.user_loader
def load_user(user_id):
    from app.models.user import User
    return User.query.get(user_id)


db = flask_sqlalchemy.SQLAlchemy()
migrate = flask_migrate.Migrate(db=db)

def create_app(config_name):
    app = flask.Flask(__name__)
    app.config.from_object(config[config_name])

    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app)

    from app.routes.main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from app.routes.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from app.routes.accounts import accounts as accounts_blueprint
    app.register_blueprint(accounts_blueprint, url_prefix='/accounts')

    return app
