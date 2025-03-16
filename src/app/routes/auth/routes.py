import logging
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, current_user
from app.models.user import User, Role
from app.crud.user import create_user, get_user_by_email, get_user_by_username, update_user, delete_user, add_user_session, remove_user_session, get_user_sessions
from app.routes.auth.forms import RegistrationForm, LoginForm, UpdateUserForm, TwoFactorForm
from app.extensions import db
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
from functools import wraps
from app.decorators.auth_decorators import login_required, requires_roles, session_required

auth = Blueprint('auth', __name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

def log_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error in {f.__name__}: {e}")
            flash('An error occurred. Please try again later.')
            # Return a redirect to a safe page when an exception occurs
            return redirect(url_for('main.index'))
            
    return decorated_function

@auth.route('/register', methods=['GET', 'POST'])
@log_errors
def register():
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Check if this will be the first user
        is_first_user = User.query.count() == 0
        
        user = create_user(form.username.data, form.email.data, form.password.data, form.phone_number.data, form.otp_type.data)
        
        if is_first_user:
            flash('Congratulations! You are registered as the System Administrator.')
        else:
            flash('Congratulations, you are now a registered user!')
            
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)

@auth.route('/login', methods=['GET', 'POST'])
@log_errors
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = get_user_by_email(form.username.data) or get_user_by_username(form.username.data)
        if user and user.verify_password(form.password.data):
            if user.two_factor_enabled:
                session['user_id'] = user.id
                return redirect(url_for('auth.two_factor'))
            login_user(user, remember=form.remember_me.data)
            user.add_session(request.user_agent.string, request.remote_addr, datetime.now(), datetime.now())
            return redirect(url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)

@auth.route('/two_factor', methods=['GET', 'POST'])
@log_errors
def two_factor():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    form = TwoFactorForm()
    user = User.query.get(session['user_id'])
    
    if form.validate_on_submit():
        if user.verify_totp(form.token.data):
            login_user(user)
            user.add_session(request.user_agent.string, request.remote_addr, datetime.now(), datetime.now())
            session.pop('user_id', None)
            return redirect(url_for('main.index'))
        else:
            flash('Invalid 2FA token.')
    
    return render_template('auth/two_factor.html', form=form)

@auth.route('/logout')
@login_required
@log_errors
def logout():
    current_device = request.user_agent.string
    current_ip = request.remote_addr
    sessions = get_user_sessions(current_user.id)
    for session in sessions:
        if session.device == current_device and session.ip_address == current_ip:
            remove_user_session(current_user.id, session.id)
            break
   

    logout_user()
    return redirect(url_for('main.index'))

@auth.route('/reset_password_request', methods=['GET', 'POST'])
@log_errors
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        email = request.form['email']
        user = get_user_by_email(email)
        if user:
            logging.info(f"Password reset requested for {email}")
            flash('Check your email for the instructions to reset your password')
        else:
            logging.info(f"Password reset requested for non-existent email {email}")
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password_request.html')

@auth.route('/reset_password/<token>', methods=['GET', 'POST'])
@log_errors
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    user = verify_reset_token(token)
    if not user:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        password = request.form['password']
        user.password = password
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html')

def generate_reset_token(user, expires_sec=1800):
    s = URLSafeTimedSerializer('SECRET_KEY')
    return s.dumps(user.email, salt='password-reset-salt')

def verify_reset_token(token, expires_sec=1800):
    s = URLSafeTimedSerializer('SECRET_KEY')
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=expires_sec)
    except Exception as e:
        logging.error(f"Error verifying reset token: {e}")
        return None
    return get_user_by_email(email)

@auth.route('/manage_sessions')
@login_required
@session_required
@log_errors
def manage_sessions():
    sessions = get_user_sessions(current_user.id)
    return render_template('auth/manage_sessions.html', sessions=sessions)

@auth.route('/remove_session/<int:session_id>')
@login_required
@session_required
@log_errors
def remove_session(session_id):
    if remove_user_session(current_user.id, session_id):
        flash('Session removed successfully.')
    else:
        flash('Failed to remove session.')
    return redirect(url_for('auth.manage_sessions'))

@auth.route('/logout_all_sessions')
@login_required
@session_required
@log_errors
def logout_all_sessions():
    sessions = get_user_sessions(current_user.id)
    for session in sessions:
        remove_user_session(current_user.id, session.id)
    logout_user()
    flash('You have been logged out from all sessions.')
    return redirect(url_for('auth.login'))
