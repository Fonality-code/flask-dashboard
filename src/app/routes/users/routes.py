from flask import Blueprint, request, render_template, flash, redirect, url_for, abort, current_app
from flask_login import login_required, current_user
from app.models.user import User, Role, requires_roles
from app.extensions import db
from app.crud.user import get_user_by_id, get_user_by_email
import uuid
from datetime import datetime, timedelta
from functools import wraps
from app.utils.email import send_email

# Create blueprint
users_bp = Blueprint('users', __name__, url_prefix='/users')

# Create model for invitations
class Invitation(db.Model):
    __tablename__ = 'invitation'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.now)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    
    role = db.relationship('Role')
    creator = db.relationship('User')

# Helper function to require admin role
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        
        # # Check if user has admin or system_admin role
        # admin_role = Role.query.filter_by(name='admin').first()
        # system_admin_role = Role.query.filter_by(name='system_admin').first()
        # if not admin_role or not system_admin_role or (admin_role not in current_user.roles and system_admin_role not in current_user.roles):
        #     flash('You do not have permission to access this page.', 'error')
        #     return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

# CRUD operations for invitations
def create_invitation(email, role_id, created_by):
    # Check if invitation already exists
    existing = Invitation.query.filter_by(email=email, used=False).first()
    if existing:
        db.session.delete(existing)  # Delete existing unused invitation
        
    # Create new invitation
    token = str(uuid.uuid4())
    expires_at = datetime.now() + timedelta(days=7)
    invitation = Invitation(email=email, token=token, role_id=role_id, 
                           created_by=created_by, expires_at=expires_at)
    db.session.add(invitation)
    db.session.commit()
    return invitation

def get_invitation_by_token(token):
    return Invitation.query.filter_by(token=token, used=False).first()

# Routes
@users_bp.route('/')
@login_required
@requires_roles('admin', 'system_admin')
def index():
    users = User.query.all()
    return render_template('users/index.html', users=users)

@users_bp.route('/add', methods=['GET', 'POST'])
@login_required
@requires_roles('admin', 'system_admin')
def add():
    roles = Role.query.all()
    
    if request.method == 'POST':
        email = request.form.get('email')
        role_id = request.form.get('role')
        
        if not email or not role_id:
            flash('Email and role are required.', 'error')
            return render_template('users/add.html', roles=roles)
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('A user with this email already exists.', 'error')
            return render_template('users/add.html', roles=roles)
        
        # Create invitation
        invitation = create_invitation(email, role_id, current_user.id)
        
        # Generate invite URL
        invite_url = url_for('users.register', token=invitation.token, _external=True)
        
        # Send email invitation
        subject = "You've been invited to join the dashboard"
        body = f"""
        You have been invited to join the dashboard. 
        
        Please click the link below to complete your registration:
        {invite_url}
        
        This invitation will expire in 7 days.
        """
        
        try:
            send_email(email, subject, body)
            flash(f'Invitation sent to {email}.', 'success')
        except Exception as e:
            flash(f'Error sending invitation: {str(e)}', 'error')
        
        return redirect(url_for('users.index'))
    
    return render_template('users/add.html', roles=roles)

@users_bp.route('/invitations')
@login_required
@requires_roles('admin', 'system_admin')
def invitations():
    active_invitations = Invitation.query.filter_by(used=False).filter(Invitation.expires_at > datetime.now()).all()
    return render_template('users/invitations.html', invitations=active_invitations)

@users_bp.route('/register/<token>', methods=['GET', 'POST'])
def register(token):
    invitation = get_invitation_by_token(token)
    
    if not invitation:
        flash('Invalid or expired invitation.', 'error')
        return redirect(url_for('auth.login'))
    
    if invitation.expires_at < datetime.now():
        flash('This invitation has expired.', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('users/register.html', invitation=invitation)
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('users/register.html', invitation=invitation)
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken.', 'error')
            return render_template('users/register.html', invitation=invitation)
        
        # Create the user
        user = User(username=username, email=invitation.email)
        user.password = password
        
        # Add role from invitation
        if invitation.role:
            user.roles.append(invitation.role)
        
        # Mark invitation as used
        invitation.used = True
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! You can now login.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('users/register.html', invitation=invitation)

# Delete user
@users_bp.route('/delete/<int:user_id>', methods=['POST'])
@login_required
@requires_roles('admin', 'system_admin')
def delete_user(user_id):
    user = get_user_by_id(user_id)
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users.index'))
    
    # Don't allow deleting yourself
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('users.index'))
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
    
    return redirect(url_for('users.index'))

# Edit user roles
@users_bp.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@requires_roles('admin', 'system_admin')
def edit_user(user_id):
    user = get_user_by_id(user_id)
    roles = Role.query.all()
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users.index'))
    
    if request.method == 'POST':
        role_ids = request.form.getlist('roles')
        selected_roles = Role.query.filter(Role.id.in_(role_ids)).all()
        
        user.roles = selected_roles
        db.session.commit()
        
        flash('User roles updated.', 'success')
        return redirect(url_for('users.index'))
    
    return render_template('users/edit.html', user=user, roles=roles)

@users_bp.route('/manage_roles/<int:user_id>', methods=['GET', 'POST'])
@login_required
@requires_roles('admin', 'system_admin')
def manage_role(user_id):
    user = get_user_by_id(user_id)
    roles = Role.query.all()
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('users.index'))
    
    if request.method == 'POST':
        role_ids = request.form.getlist('roles')
        selected_roles = Role.query.filter(Role.id.in_(role_ids)).all()
        
        user.roles = selected_roles
        db.session.commit()
        
        flash('User roles updated.', 'success')
        return redirect(url_for('users.index'))
    
    return render_template('users/manage_roles.html', user=user, roles=roles)

@users_bp.route('/roles')
@login_required
@requires_roles('admin', 'system_admin')
def view_roles():
    roles = Role.query.all()
    return render_template('users/view_roles.html', roles=roles)

@users_bp.route('/roles/manage', methods=['GET', 'POST'])
@login_required
@requires_roles('admin', 'system_admin')
def manage_roles():
    if request.method == 'POST':
        role_name = request.form.get('role_name')
        role_description = request.form.get('role_description')
        
        if not role_name:
            flash('Role name is required.', 'error')
            return redirect(url_for('users.manage_roles'))
        
        role = Role(name=role_name, description=role_description)
        db.session.add(role)
        db.session.commit()
        
        flash('Role created successfully.', 'success')
        return redirect(url_for('users.view_roles'))
    
    return render_template('users/manage_roles.html')
