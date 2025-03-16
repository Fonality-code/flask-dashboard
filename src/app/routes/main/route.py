from flask import Blueprint, render_template
from app.decorators.auth_decorators import login_required, requires_roles, session_required
from app.models.settings import Settings

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    ui_settings = Settings.get_ui_settings()
    return render_template('index.html', ui_settings=ui_settings)
