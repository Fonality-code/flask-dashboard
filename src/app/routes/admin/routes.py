import os
from flask import Blueprint, render_template, current_app
from flask_login import login_required, current_user
from app.decorators.auth_decorators import requires_roles

admin = Blueprint('admin', __name__)

@admin.route('/')
@login_required
@requires_roles('system_admin')
def index():
    return render_template('admin/index.html')

@admin.route('/logs')
@login_required
@requires_roles('system_admin')
def view_logs():
    log_file_path = os.path.join(current_app.root_path, 'logs', 'app.log')
    with open(log_file_path, 'r') as log_file:
        logs = log_file.readlines()
    return render_template('admin/logs.html', logs=logs)
