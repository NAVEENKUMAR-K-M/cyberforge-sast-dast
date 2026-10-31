"""pyshop: a deliberately vulnerable shop used to test the scanners. Never expose it."""
from flask import Flask

from . import config
from .db import close_db, init_db


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY
    init_db()
    app.teardown_appcontext(close_db)

    from .admin import bp as admin_bp
    from .auth import bp as auth_bp
    from .files import bp as files_bp
    from .orders import bp as orders_bp
    from .products import bp as products_bp
    from .tools import api as api_bp
    from .tools import bp as tools_bp
    from .web import bp as web_bp

    for blueprint in (web_bp, products_bp, orders_bp, auth_bp, tools_bp, api_bp, admin_bp, files_bp):
        app.register_blueprint(blueprint)

    @app.after_request
    def headers(response):
        response.headers["Server"] = "pyshop-gunicorn/21.2.0"
        response.headers["X-Powered-By"] = "Flask/3.0.3 Python/3.12"
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    return app
