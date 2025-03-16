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
from app.extensions import oauth
import os
import secrets

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

@auth.route('/register/google')
def google_register():
    redirect_uri = url_for('auth.google_register_callback', _external=True)
    nonce = secrets.token_urlsafe()
    session['google_nonce'] = nonce
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@auth.route('/register/google/callback')
def google_register_callback():
    token = oauth.google.authorize_access_token()
    nonce = session.pop('google_nonce', None)
    user_info = oauth.google.parse_id_token(token, nonce=nonce)

    user = User.query.filter_by(email=user_info['email']).first()
    if user:
        flash('An account with this email already exists. Please log in.')
        return redirect(url_for('auth.login'))

    user = create_user(
        username=user_info['email'],
        email=user_info['email'],
        password=None,
        phone_number=None,
        otp_type=None
    )
    user.first_name = user_info.get('given_name')
    user.last_name = user_info.get('family_name')
    user.link_google_account(user_info['sub'])
    db.session.commit()

    login_user(user)
    return redirect(url_for('main.index'))

@auth.route('/login', methods=['GET', 'POST'])
@log_errors
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = get_user_by_email(form.username.data) or get_user_by_username(form.username.data)
        if user:
            if user.is_account_locked():
                flash('Your account is locked due to multiple failed login attempts. Please try again later.')
                logging.warning(f"Locked account login attempt for user {user.username}.")
                return redirect(url_for('auth.login'))

            if user.verify_password(form.password.data):
                user.reset_failed_logins()
                if user.two_factor_enabled:
                    session['user_id'] = user.id
                    if user.otp_type == 'email':
                        user.generate_email_otp()
                    elif user.otp_type == 'phone':
                        user.generate_phone_otp()
                    return redirect(url_for('auth.two_factor'))
                login_user(user, remember=form.remember_me.data)
                user.add_session(request.user_agent.string, request.remote_addr, datetime.now(), datetime.now())
                logging.info(f"User {user.username} logged in successfully.")
                return redirect(url_for('main.index'))
            else:
                user.increment_failed_logins()
                logging.warning(f"Failed login attempt for user {user.username}.")
                flash('Invalid username or password.')
        else:
            logging.warning(f"Failed login attempt with non-existent username/email: {form.username.data}.")
            flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)

@auth.route('/login/google')
def google_login():
    redirect_uri = url_for('auth.google_callback', _external=True)
    nonce = secrets.token_urlsafe()
    session['google_nonce'] = nonce
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@auth.route('/login/google/callback')
def google_callback():
    token = oauth.google.authorize_access_token()
    nonce = session.pop('google_nonce', None)
    user_info = oauth.google.parse_id_token(token, nonce=nonce)

    google_id = user_info['sub']
    user = User.query.filter_by(google_id=google_id).first()
    if user is None:
        flash('No account linked with this Google account. Please register first.')
        return redirect(url_for('auth.register'))
    
    if user is None or user.google_id != user_info['sub']:
        flash('No account linked with this Google account. Please link your Google account first.')
        return redirect(url_for('auth.login'))
    

    # if user has 2FA enabled, send OTP
    if user.two_factor_enabled:
        session['user_id'] = user.id
        if user.otp_type == 'email':
            user.generate_email_otp()
        elif user.otp_type == 'phone':
            user.generate_phone_otp()
        return redirect(url_for('auth.two_factor'))
    

    login_user(user)

    # add session
    user.add_session(request.user_agent.string, request.remote_addr, datetime.now(), datetime.now())
    
    return redirect(url_for('main.index'))

@auth.route('/account/link_google')
@login_required
@log_errors
def link_google():
    redirect_uri = url_for('auth.link_google_callback', _external=True)
    nonce = secrets.token_urlsafe()
    session['google_nonce'] = nonce
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@auth.route('/account/link_google/callback')
@login_required
@log_errors
def link_google_callback():
    token = oauth.google.authorize_access_token()
    nonce = session.pop('google_nonce', None)
    user_info = oauth.google.parse_id_token(token, nonce=nonce)

    if current_user.google_id is not None and current_user.google_id != user_info['sub']:
        flash('This Google account is already linked to another user.')
        return redirect(url_for('account.security'))

    current_user.link_google_account(user_info['sub'])
    flash('Google account linked successfully.')
    return redirect(url_for('account.security'))

@auth.route('/two_factor', methods=['GET', 'POST'])
@log_errors
def two_factor():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    form = TwoFactorForm()
    user = User.query.get(session['user_id'])
    
    if form.validate_on_submit():
        if user.verify_otp(form.token.data):
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

@auth.route('/account/change_auth_type', methods=['POST'])
@login_required
@log_errors
def change_auth_type():
    otp_type = request.form.get('otp_type')
    if otp_type and otp_type in ['email', 'phone', 'app']:
        current_user.otp_type = otp_type
        db.session.commit()
        # Send verification code based on the selected OTP type
        if otp_type == 'email':
            current_user.generate_email_otp()
        elif otp_type == 'phone':
            current_user.generate_phone_otp()
        elif otp_type == 'app':
            current_user.generate_totp_secret()
            return redirect(url_for('account.security'))
        flash('Verification code sent. Please verify to activate the new authentication method.')
        session['user_id'] = current_user.id
        return redirect(url_for('auth.two_factor'))
    

    flash('Invalid authentication type selected.')
    return redirect(url_for('account.security'))
