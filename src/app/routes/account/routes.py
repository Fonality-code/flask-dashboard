from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.crud.user import update_user, get_user_sessions, remove_user_session
from app.routes.account.forms import UpdateAccountForm, UpdateUserOptionsForm
from app.routes.auth.forms import TwoFactorForm  # Corrected import
from datetime import datetime
from werkzeug.utils import secure_filename
import os
from app.decorators.auth_decorators import login_required, session_required

account = Blueprint('account', __name__)

@account.route('/')
@login_required
@session_required
def index():
    # Get the user's active sessions
    sessions = get_user_sessions(current_user.id)
    
    # Get the user's most recent session for device info
    current_device = "Unknown"
    if sessions:
        most_recent_session = max(sessions, key=lambda s: s.last_active)
        current_device = most_recent_session.device
    
    # Update the current_user with the active device info if not set
    if not current_user.active_device and current_device != "Unknown":
        current_user.active_device = current_device
        current_user.last_login = datetime.now()
        from app.extensions import db
        db.session.commit()
    
    return render_template('account/index.html', active_sessions=sessions)

@account.route('/details', methods=['GET', 'POST'])
@login_required
@session_required
def details():
    form = UpdateAccountForm(obj=current_user)
    options_form = UpdateUserOptionsForm(obj=current_user)
    if form.validate_on_submit() and options_form.validate_on_submit():
        # Handle profile image upload
        if options_form.profile_image.data:
            filename = secure_filename(options_form.profile_image.data.filename)
            filepath = os.path.join('uploads/profile_images', filename)
            options_form.profile_image.data.save(filepath)
            current_user.profile_image = filepath
        
        update_user(current_user.id, form.username.data, form.email.data, form.phone_number.data,
                    options_form.first_name.data, options_form.last_name.data, current_user.profile_image)
        flash('Your account details have been updated.')
        return redirect(url_for('account.details'))
    return render_template('account/details.html', form=form, options_form=options_form)

@account.route('/security', methods=['GET', 'POST'])
@login_required
@session_required
def security():
    form = TwoFactorForm()
    if request.method == 'POST':
        if 'enable_2fa' in request.form:
            current_user.enable_two_factor()
            flash('Two-factor authentication has been enabled.', 'success')
        elif 'disable_2fa' in request.form:
            current_user.disable_two_factor()
            flash('Two-factor authentication has been disabled.', 'success')
        elif form.validate_on_submit():
            if current_user.verify_totp(form.token.data):
                flash('Two-factor authentication confirmed.', 'success')
            else:
                flash('Invalid 2FA token.', 'error')
    
    # Generate QR code for 2FA setup if enabled
    qr_code = None
    if current_user.two_factor_enabled and current_user.totp_secret:
        import pyotp
        import qrcode
        import io
        import base64
        
        totp = pyotp.TOTP(current_user.totp_secret)
        uri = totp.provisioning_uri(current_user.email, issuer_name="Dashboard App")
        
        # Generate QR code
        img = qrcode.make(uri)
        buffered = io.BytesIO()
        img.save(buffered)
        qr_code = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('account/security.html', form=form, qr_code=qr_code)

@account.route('/enable-2fa', methods=['POST'])
@login_required
@session_required
def enable_2fa():
    current_user.enable_two_factor()
    flash('Two-factor authentication has been enabled.')
    return redirect(url_for('account.details'))

@account.route('/change_auth_type', methods=['POST'])
@login_required
@session_required
def change_auth_type():
    if request.method == 'POST':
        otp_type = request.form.get('otp_type')
        if otp_type in ['app', 'email', 'phone']:
            current_user.otp_type = otp_type
            from app.extensions import db
            db.session.commit()
            flash(f'Authentication method updated to {otp_type}.', 'success')
        else:
            flash('Invalid authentication type selected.', 'error')
    return redirect(url_for('account.security'))

@account.route('/sessions')
@login_required
@session_required
def sessions():
    sessions = get_user_sessions(current_user.id)
    return redirect(url_for('auth.manage_sessions'))

@account.route('/sessions/remove/<int:session_id>', methods=['POST'])
@login_required
@session_required
def remove_session(session_id):
    if remove_user_session(current_user.id, session_id):
        flash('Session has been revoked successfully.', 'success')
    else:
        flash('Error revoking session.', 'error')
    return redirect(url_for('account.sessions'))
