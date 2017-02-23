class Config(object):
    DEBUG = False
    TESTING = False
    SECRET_KEY = None
    LOGGER_NAME = None
    TRAP_HTTP_EXCEPTIONS = False
    TRAP_BAD_REQUEST_ERRORS = False
    TEMPLATES_AUTO_RELOAD = False
    EXPLAIN_TEMPLATE_LOADING = False
    # DB URI


class DevConfig(Config):
    DEBUG = True
    TRAP_HTTP_EXCEPTIONS = True
    TEMPLATES_AUTO_RELOAD = True
    EXPLAIN_TEMPLATE_LOADING = True
    TRAP_BAD_REQUEST_ERRORS = True


class TestConfig(Config):
    TESTING = True
