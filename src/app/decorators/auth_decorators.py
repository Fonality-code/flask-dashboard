from functools import wraps
from flask import redirect, url_for, flash, abort, request
from flask_login import current_user, logout_user
from flask import current_app


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page', 'error')
                return redirect(url_for('auth.login'))
                
            user_roles = [role.name for role in current_user.roles]
            if not any(role in user_roles for role in roles):
                abort(403)  # Forbidden
                
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

def session_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        current_app.logger.info(f"Current user: {current_user.active_device}")
        
        if not current_user.is_authenticated:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('auth.login'))
        
        from app.models.user import UserSession  # Moved import inside the function
        active_sessions = UserSession.query.filter_by(user_id=current_user.id).all()


        current_device = request.user_agent.string
        current_ip = request.remote_addr
        
        if not any(session.device == current_device and session.ip_address == current_ip for session in active_sessions):
            flash('Session expired. Please log in again.', 'error')
            logout_user()
            return redirect(url_for('auth.login'))
        
        
        return f(*args, **kwargs)
    return decorated_function
