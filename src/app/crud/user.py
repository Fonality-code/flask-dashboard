from app.models.user import User
from app.extensions import db

def create_user(username, email, password, phone_number=None, otp_type=None):
    user = User(username=username, email=email, phone_number=phone_number, otp_type=otp_type)
    user.password = password
    db.session.add(user)
    db.session.commit()
    return user

def get_user_by_id(user_id):
    return User.query.get(user_id)

def get_user_by_username(username):
    return User.query.filter_by(username=username).first()

def get_user_by_email(email):
    return User.query.filter_by(email=email).first()

def update_user(user_id, **kwargs):
    user = get_user_by_id(user_id)
    if user:
        for key, value in kwargs.items():
            setattr(user, key, value)
        db.session.commit()
    return user

def delete_user(user_id):
    user = get_user_by_id(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    return user

def add_user_session(user_id, device, ip_address, login_time, last_active):
    user = get_user_by_id(user_id)
    if user:
        return user.add_session(device, ip_address, login_time, last_active)
    return None

def remove_user_session(user_id, session_id):
    user = get_user_by_id(user_id)
    if user:
        return user.remove_session(session_id)
    return False

def get_user_sessions(user_id):
    user = get_user_by_id(user_id)
    if user:
        return user.get_active_sessions()
    return []
