from flask import Blueprint, render_template
from flask_login import login_required
from app.models.settings import Settings

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@login_required
def index():
    ui_settings = Settings.get_ui_settings()
    return render_template('index.html', ui_settings=ui_settings)
