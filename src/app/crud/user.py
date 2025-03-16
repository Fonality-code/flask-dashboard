from app.models.user import User, Role
from app.extensions import db

def create_user(username, email, password, phone_number=None, otp_type=None):
    user = User(username=username, email=email, phone_number=phone_number, otp_type=otp_type)
    user.password = password
    
    # Check if this is the first user, if so, make them a system admin
    user_count = User.query.count()
    if user_count == 0:
        # Get or create admin role
        admin_role = Role.query.filter_by(name='system_admin').first()
        if not admin_role:
            admin_role = Role(name='system_admin', description='System Administrator with full access')
            db.session.add(admin_role)
            db.session.flush()  # Flush to get the role ID without committing
        
        # Assign admin role to user
        user.roles.append(admin_role)
    
    db.session.add(user)
    db.session.commit()
    return user

def get_user_by_id(user_id):
    return User.query.get(user_id)

def get_user_by_username(username):
    return User.query.filter_by(username=username).first()

def get_user_by_email(email):
    return User.query.filter_by(email=email).first()

def update_user(user_id, username, email, phone_number, first_name=None, last_name=None, profile_image=None):
    user = get_user_by_id(user_id)
    if user:
        user.username = username
        user.email = email
        user.phone_number = phone_number
        user.first_name = first_name
        user.last_name = last_name
        user.profile_image = profile_image
        db.session.commit()
    return user

def enable_two_factor_auth(user_id):
    user = get_user_by_id(user_id)
    if user:
        user.enable_two_factor()
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
