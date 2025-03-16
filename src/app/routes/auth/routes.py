import logging
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.models.user import User
from app.crud.user import create_user, get_user_by_email, get_user_by_username, update_user, delete_user, add_user_session, remove_user_session, get_user_sessions
from app.routes.auth.forms import RegistrationForm, LoginForm, UpdateUserForm
from app.extensions import db
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
from functools import wraps

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
            
    return decorated_function

@auth.route('/register', methods=['GET', 'POST'])
@log_errors
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = create_user(form.username.data, form.email.data, form.password.data, form.phone_number.data, form.otp_type.data)
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
            login_user(user, remember=form.remember_me.data)
            user.add_session(request.user_agent.string, request.remote_addr, datetime.utcnow(), datetime.utcnow())
            return redirect(url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
@log_errors
def logout():
    current_user.remove_session(current_user.get_id())
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
@log_errors
def manage_sessions():
    sessions = get_user_sessions(current_user.id)
    return render_template('auth/manage_sessions.html', sessions=sessions)

@auth.route('/remove_session/<int:session_id>')
@login_required
@log_errors
def remove_session(session_id):
    if remove_user_session(current_user.id, session_id):
        flash('Session removed successfully.')
    else:
        flash('Failed to remove session.')
    return redirect(url_for('auth.manage_sessions'))

@auth.route('/logout_all_sessions')
@login_required
@log_errors
def logout_all_sessions():
    sessions = get_user_sessions(current_user.id)
    for session in sessions:
        remove_user_session(current_user.id, session.id)
    logout_user()
    flash('You have been logged out from all sessions.')
    return redirect(url_for('auth.login'))
