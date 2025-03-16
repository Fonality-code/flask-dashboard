import logging
from logging.handlers import RotatingFileHandler
import os
from flask import Flask
from app.extensions import db, login_manager, oauth
from app.routes import registerBlueprints
from app.models.user import User
from app.models.settings import Settings

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    oauth.init_app(app)

    # Configure Google OAuth
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
        client_kwargs={
            'scope': 'openid email profile',
        }
    )

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
    
    # Configure logging
    log_dir = os.path.join(app.root_path, 'logs')
    if not os.path.exists(log_dir):
        os.mkdir(log_dir)
    file_handler = RotatingFileHandler(os.path.join(log_dir, 'app.log'), maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

    # Ensure that all loggers use the same file handler
    logging.getLogger().addHandler(file_handler)

    with app.app_context():
        db.create_all()

    return app
