from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from app.extensions import db


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
    device = db.Column(db.String(128), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    login_time = db.Column(db.DateTime, nullable=False)
    last_active = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', backref=db.backref('sessions', lazy='dynamic'))

    def __repr__(self):
        return f'<UserSession {self.device} - {self.ip_address}>'

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    first_name = db.Column(db.String(64), nullable=True)
    last_name = db.Column(db.String(64), nullable=True)
    profile_image = db.Column(db.String(128), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
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

    # Security recommendations:
    # 1. Ensure passwords are hashed using a strong algorithm (e.g., bcrypt).
    # 2. Enforce strong password policies (e.g., minimum length, complexity).
    # 3. Implement account lockout mechanisms after multiple failed login attempts.
    # 4. Use HTTPS to protect data in transit.
    # 5. Regularly review and update security practices.
    # 6. Implement logging and monitoring for suspicious activities.
    # 7. Educate users about phishing and social engineering attacks.
