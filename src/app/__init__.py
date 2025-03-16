from flask import Flask
from app.extensions import db, login_manager
from app.routes import registerBlueprints
from app.models.user import User
from app.models.settings import Settings

def create_app(config_name='default'):
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
    
    # Context processor to make ui_settings available to all templates
    @app.context_processor
    def inject_ui_settings():
        ui_settings = Settings.get_ui_settings()
        return dict(ui_settings=ui_settings)
    
    with app.app_context():
        db.create_all()

    return app
