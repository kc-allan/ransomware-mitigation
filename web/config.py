class Config:
    SECRET_KEY = 'jbdiuyh87hd8376rtvbc6b7erb627r1vcineuq7nesz3re'


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    USE_RELOADER = True


class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class TestingConfig(Config):
    DEBUG = True
    TESTING = True


config = {
    'default': DevelopmentConfig,
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}
