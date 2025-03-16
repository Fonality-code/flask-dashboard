from flask import Flask
from app.routes.auth.routes import auth
from app.routes.main.route import main_bp
from app.routes.account.routes import account
from app.routes.users.routes import users_bp
from app.routes.settings import settings_bp
from app.routes.admin.routes import admin

def registerBlueprints(app: Flask):
    app.register_blueprint(auth)
    app.register_blueprint(main_bp)
    app.register_blueprint(account, url_prefix='/account')
    app.register_blueprint(users_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(admin, url_prefix='/admin')