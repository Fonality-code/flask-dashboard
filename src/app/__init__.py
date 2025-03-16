from flask import Flask
from app.extensions import db, login_manager
from app.routes import registerBlueprints
from app.models.user import User

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)

    # Register blueprints
    registerBlueprints(app)

    # User loader function
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    

    with app.app_context():
        db.create_all()

    return app  # Register the users blueprint
    
    return app
