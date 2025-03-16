import logging
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from app.extensions import db
from datetime import datetime, timedelta
from functools import wraps
from flask import abort, flash, redirect, url_for
from app.decorators.auth_decorators import login_required, requires_roles, session_required
from app.utils.email import send_email
from app.utils.sms import send_sms


# Association table for many-to-many relationship between users and roles
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'))
)

class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(128))

    def __repr__(self):
        return f'<Role {self.name}>'

class UserSession(db.Model):
    __tablename__ = 'user_session'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    device = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(100), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.now, nullable=False)
    last_active = db.Column(db.DateTime, default=datetime.now, nullable=False)

    user = db.relationship('User', back_populates='sessions')

    def __repr__(self):
        return f'<UserSession {self.device} - {self.ip_address}>'

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    first_name = db.Column(db.String(150), nullable=True)
    last_name = db.Column(db.String(150), nullable=True)
    profile_image = db.Column(db.String(200), nullable=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=True)
    otp_type = db.Column(db.String(10), nullable=True)  # 'email', 'phone', 'app'
    password_hash = db.Column(db.String(128), nullable=False)
    active = db.Column(db.Boolean, default=True)
    fs_token_uniquifier = db.Column(db.String(64), unique=True, nullable=True)
    fs_webauthn_user_handle = db.Column(db.String(64), unique=True, nullable=True)
    mf_recovery_codes = db.Column(db.Text, nullable=True)
    roles = db.relationship('Role', secondary=user_roles, backref=db.backref('users', lazy='dynamic'))

    # Two-Factor Authentication fields
    totp_secret = db.Column(db.String(16), nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime, nullable=True)
    active_device = db.Column(db.String(200), nullable=True)
    email_otp = db.Column(db.String(6), nullable=True)
    email_otp_expiry = db.Column(db.DateTime, nullable=True)
    phone_otp = db.Column(db.String(6), nullable=True)
    phone_otp_expiry = db.Column(db.DateTime, nullable=True)
    google_id = db.Column(db.String(128), unique=True, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    lockout_time = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_totp_secret(self):
        self.totp_secret = pyotp.random_base32()
        db.session.commit()

    def verify_totp(self, token):
        if self.totp_secret:
            totp = pyotp.TOTP(self.totp_secret)
            return totp.verify(token)
        return False

    def enable_two_factor(self):
        self.two_factor_enabled = True
        self.generate_totp_secret()
        db.session.commit()

    def disable_two_factor(self):
        self.two_factor_enabled = False
        self.totp_secret = None
        db.session.commit()

    def generate_recovery_codes(self):
        import secrets
        codes = [secrets.token_hex(8) for _ in range(10)]
        self.mf_recovery_codes = ','.join(codes)
        db.session.commit()
        return codes

    def add_session(self, device, ip_address, login_time, last_active):
        session = UserSession(user_id=self.id, device=device, ip_address=ip_address, login_time=login_time, last_active=last_active)
        db.session.add(session)
        db.session.commit()
        return session

    def remove_session(self, session_id):
        session = UserSession.query.get(session_id)
        if session and session.user_id == self.id:
            db.session.delete(session)
            db.session.commit()
            return True
        return False

    def get_active_sessions(self):
        return UserSession.query.filter_by(user_id=self.id).all()

    def generate_email_otp(self):
        import secrets
        self.email_otp = secrets.token_hex(3)  # Generate a 6-character OTP
        self.email_otp_expiry = datetime.now() + timedelta(minutes=10)  # OTP valid for 10 minutes
        db.session.commit()
        # Send the OTP to the user's email
        send_email(self.email, 'Your OTP Code', f'Your OTP code is {self.email_otp}')

    def verify_email_otp(self, token):
        if self.email_otp and self.email_otp_expiry > datetime.now():
            return self.email_otp == token
        return False

    def generate_phone_otp(self):
        import secrets
        self.phone_otp = secrets.token_hex(3)  # Generate a 6-character OTP
        self.phone_otp_expiry = datetime.now() + timedelta(minutes=10)  # OTP valid for 10 minutes
        db.session.commit()
        # Send the OTP to the user's phone
        send_sms(self.phone_number, f'Your OTP code is {self.phone_otp}')

    def verify_phone_otp(self, token):
        if self.phone_otp and self.phone_otp_expiry > datetime.now():
            return self.phone_otp == token
        return False

    def verify_otp(self, token):
        if self.otp_type == 'email':
            return self.verify_email_otp(token)
        elif self.otp_type == 'phone':
            return self.verify_phone_otp(token)
        elif self.otp_type == 'app':
            return self.verify_totp(token)
        return False

    def link_google_account(self, google_id):
        self.google_id = google_id
        db.session.commit()

    def is_google_account_linked(self):
        return self.google_id is not None

    def increment_failed_logins(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.lockout_time = datetime.now() + timedelta(minutes=15)  # Lockout for 15 minutes
            self.send_suspicious_activity_email()
            logging.warning(f"User {self.username} account locked due to multiple failed login attempts.")
        db.session.commit()

    def reset_failed_logins(self):
        self.failed_login_attempts = 0
        self.lockout_time = None
        db.session.commit()

    def is_account_locked(self):
        if self.lockout_time and self.lockout_time > datetime.now():
            return True
        return False

    def send_suspicious_activity_email(self):
        send_email(
            self.email,
            'Suspicious Activity Detected',
            'We have detected multiple failed login attempts on your account. Your account has been locked for 15 minutes for security reasons.'
        )
        logging.info(f"Suspicious activity email sent to {self.email}.")

User.sessions = db.relationship('UserSession', order_by=UserSession.login_time, back_populates='user')

# Security recommendations:
# 1. Ensure passwords are hashed using a strong algorithm (e.g., bcrypt).
# 2. Enforce strong password policies (e.g., minimum length, complexity).
# 3. Implement account lockout mechanisms after multiple failed login attempts.
# 4. Use HTTPS to protect data in transit.
# 5. Regularly review and update security practices.
# 6. Implement logging and monitoring for suspicious activities.
# 7. Educate users about phishing and social engineering attacks.
