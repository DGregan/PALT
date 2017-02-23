class Config(object):
    DEBUG = False
    TESTING = False
    SECRET_KEY = None
    LOGGER_NAME = None
    TRAP_HTTP_EXCEPTIONS = False
    TEMPLATES_AUTO_RELOAD = False
    EXPLAIN_TEMPLATE_LOADING = False
    # DB URI


class DevConfig(Config):
    DEBUG = True
    TRAP_HTTP_EXCEPTIONS = True
    TEMPLATES_AUTO_RELOAD = True
    EXPLAIN_TEMPLATE_LOADING = True


class TestConfig(Config):
    TESTING = True
