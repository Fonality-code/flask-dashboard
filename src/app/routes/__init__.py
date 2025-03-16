from flask import Flask
from app.routes.auth.routes import auth
from app.routes.main.route import main



def registerBlueprints(app: Flask):
    app.register_blueprint(auth)
    app.register_blueprint(main)