from flask import Flask
from app.routes.auth.routes import auth
from app.routes.main.route import main
from app.routes.account.routes import account
from app.routes.users.routes import users_bp


def registerBlueprints(app: Flask):
    app.register_blueprint(auth)
    app.register_blueprint(main)
    app.register_blueprint(account, url_prefix='/account')
    app.register_blueprint(users_bp)