from flask import Flask, render_template, request, jsonify, redirect, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from functools import wraps
import logging
import json
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
from config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, FROM_EMAIL, EMAIL_TEMPLATES

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///incidents.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='reporter')
    specialization = db.Column(db.String(50))
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    permissions = db.Column(db.Text)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_permission(self, action, incident=None):
        permissions = {
            'admin': ['create', 'read', 'update', 'delete', 'assign', 'close', 'bulk_actions', 'user_management'],
            'manager': ['create', 'read', 'update', 'assign', 'close', 'bulk_assign'],
            'engineer': ['read', 'update_assigned', 'work_log'],
            'reporter': ['create', 'read_own', 'upload_attachment']
        }
        
        if action in permissions.get(self.role, []):
            if action == 'read_own' and incident:
                return incident.created_by == self.id
            if action == 'update_assigned' and incident:
                return incident.assigned_to == self.id
            return True
        return False

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='open')
    category = db.Column(db.String(50), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    is_deleted = db.Column(db.Boolean, default=False)
    
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_incidents')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_incidents')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    incident = db.relationship('Incident', backref='comments')
    user = db.relationship('User', backref='comments')

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    file_size = db.Column(db.Integer)
    
    incident = db.relationship('Incident', backref='attachments')
    uploader = db.relationship('User', backref='uploads')

class WorkLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    time_spent = db.Column(db.Float)
    logged_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    incident = db.relationship('Incident', backref='work_logs')
    user = db.relationship('User', backref='work_logs')

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='audit_logs')

# Auth decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def permission_required(action):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect('/login')
            
            user = User.query.get(session['user_id'])
            if not user or not user.has_permission(action):
                flash('Permission denied', 'error')
                return redirect('/dashboard')
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_audit(action, resource_type, resource_id=None, details=None):
    if 'user_id' in session:
        audit = AuditLog(
            user_id=session['user_id'],
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(audit)
        db.session.commit()

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username and password:
            user = User.query.filter_by(username=username, is_active=True).first()
            if user and user.check_password(password):
                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role
                return redirect('/dashboard')
        
        flash('Invalid credentials', 'error')
    
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'reporter')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
        else:
            user = User(username=username, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect('/login')
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    
    if user.role == 'reporter':
        incidents = Incident.query.filter_by(created_by=user.id, is_deleted=False).order_by(Incident.created_at.desc()).all()
    elif user.role == 'engineer':
        incidents = Incident.query.filter(
            (Incident.assigned_to == user.id) | (Incident.created_by == user.id),
            Incident.is_deleted == False
        ).order_by(Incident.created_at.desc()).all()
    else:
        incidents = Incident.query.filter_by(is_deleted=False).order_by(Incident.created_at.desc()).all()
    
    stats = {
        'total': len(incidents),
        'open': len([i for i in incidents if i.status == 'open']),
        'in_progress': len([i for i in incidents if i.status == 'in_progress']),
        'resolved': len([i for i in incidents if i.status == 'resolved'])
    }
    
    users = User.query.filter_by(is_active=True).all()
    return render_template('dashboard.html', incidents=incidents, stats=stats, users=users)

@app.route('/incident/new', methods=['GET', 'POST'])
@login_required
@permission_required('create')
def new_incident():
    if request.method == 'POST':
        incident = Incident(
            title=request.form['title'],
            description=request.form['description'],
            priority=request.form['priority'],
            severity=request.form['severity'],
            category=request.form['category'],
            created_by=session['user_id']
        )
        db.session.add(incident)
        db.session.commit()
        send_notification(incident, 'incident_created')
        flash('Incident created successfully', 'success')
        return redirect('/dashboard')
    return render_template('new_incident.html')

@app.route('/incident/<int:id>')
@login_required
def view_incident(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    
    if user.role == 'reporter' and incident.created_by != user.id:
        flash('Permission denied', 'error')
        return redirect('/dashboard')
    elif user.role == 'engineer' and incident.assigned_to != user.id and incident.created_by != user.id:
        flash('Permission denied', 'error')
        return redirect('/dashboard')
    
    users = User.query.filter_by(is_active=True).all()
    comments = Comment.query.filter_by(incident_id=id).order_by(Comment.created_at.asc()).all()
    work_logs = WorkLog.query.filter_by(incident_id=id).order_by(WorkLog.logged_at.desc()).all()
    attachments = Attachment.query.filter_by(incident_id=id).order_by(Attachment.uploaded_at.desc()).all()
    return render_template('incident_detail.html', incident=incident, users=users, comments=comments, work_logs=work_logs, attachments=attachments)

@app.route('/admin_panel')
@login_required
def admin_panel():
    user = User.query.get(session['user_id'])
    if user.role != 'admin':
        flash('Admin access required', 'error')
        return redirect('/dashboard')
    
    users = User.query.filter_by(is_active=True).all()
    user_count = User.query.count()
    incident_count = Incident.query.filter_by(is_deleted=False).count()
    engineer_count = User.query.filter_by(role='engineer', is_active=True).count()
    
    return render_template('admin_panel.html', 
                         users=users, 
                         user_count=user_count, 
                         incident_count=incident_count, 
                         engineer_count=engineer_count)

@app.route('/reports')
@login_required
def reports():
    user = User.query.get(session['user_id'])
    if user.role not in ['admin', 'manager']:
        flash('Access denied', 'error')
        return redirect('/dashboard')
    
    total_incidents = Incident.query.filter_by(is_deleted=False).count()
    open_incidents = Incident.query.filter_by(status='open', is_deleted=False).count()
    resolved_incidents = Incident.query.filter_by(status='resolved', is_deleted=False).count()
    critical_incidents = Incident.query.filter_by(priority='critical', is_deleted=False).count()
    
    engineers = User.query.filter_by(role='engineer', is_active=True).all()
    engineer_stats = []
    for eng in engineers:
        resolved_count = Incident.query.filter_by(assigned_to=eng.id, status='resolved').count()
        in_progress_count = Incident.query.filter_by(assigned_to=eng.id, status='in_progress').count()
        engineer_stats.append({
            'name': eng.username,
            'specialization': eng.specialization or 'General',
            'resolved': resolved_count,
            'in_progress': in_progress_count
        })
    
    engineer_stats.sort(key=lambda x: x['resolved'], reverse=True)
    
    stats = {
        'total_incidents': total_incidents,
        'open_incidents': open_incidents,
        'resolved_incidents': resolved_incidents,
        'critical_incidents': critical_incidents,
        'resolution_rate': round((resolved_incidents / total_incidents * 100) if total_incidents > 0 else 0, 1),
        'engineer_stats': engineer_stats[:10]
    }
    
    return render_template('reports.html', stats=stats)

@app.route('/bulk-actions')
@login_required
@permission_required('bulk_actions')
def bulk_actions():
    incidents = Incident.query.filter_by(is_deleted=False).all()
    users = User.query.filter_by(role='engineer', is_active=True).all()
    return render_template('bulk_actions.html', incidents=incidents, users=users)

@app.route('/audit-logs')
@login_required
def audit_logs():
    if session.get('role') != 'admin':
        flash('Admin access required', 'error')
        return redirect('/dashboard')
    
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    return render_template('audit_logs.html', logs=logs)

@app.route('/profile-settings', methods=['GET', 'POST'])
@login_required
def profile_settings():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        user.email = request.form.get('email', user.email)
        if request.form.get('password'):
            user.set_password(request.form.get('password'))
            log_audit('password_change', 'user', user.id, f'Password changed for {user.username}')
            flash('Profile and password updated successfully', 'success')
        else:
            flash('Profile updated successfully', 'success')
        db.session.commit()
        return redirect('/profile-settings')
    
    days_active = (datetime.utcnow() - user.created_at).days
    comment_count = Comment.query.filter_by(user_id=user.id).count()
    
    if user.role == 'admin':
        total_users = User.query.count()
        total_incidents = Incident.query.filter_by(is_deleted=False).count()
        stats = {'total_users': total_users, 'total_incidents': total_incidents}
    elif user.role == 'manager':
        team_size = User.query.filter_by(role='engineer').count()
        managed_incidents = Incident.query.filter_by(is_deleted=False).count()
        stats = {'team_size': team_size, 'managed_incidents': managed_incidents}
    elif user.role == 'engineer':
        resolved_count = Incident.query.filter_by(assigned_to=user.id, status='resolved').count()
        in_progress_count = Incident.query.filter_by(assigned_to=user.id, status='in_progress').count()
        stats = {'resolved': resolved_count, 'in_progress': in_progress_count}
    elif user.role == 'reporter':
        created_count = Incident.query.filter_by(created_by=user.id).count()
        resolved_count = Incident.query.filter_by(created_by=user.id, status='resolved').count()
        stats = {'created': created_count, 'resolved': resolved_count}
    else:
        stats = {}
    
    return render_template('profile_settings.html', user=user, days_active=days_active, stats=stats, comment_count=comment_count)

# API Routes
@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    user = User.query.get(session['user_id'])
    if user.role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    new_user = User(
        username=data['username'],
        email=data['email'],
        role=data['role'],
        specialization=data.get('specialization'),
        permissions=json.dumps(data.get('permissions', []))
    )
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()
    
    log_audit('create_user', 'user', new_user.id, f'Created user {data["username"]}')
    return jsonify({'success': True, 'user_id': new_user.id})

@app.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    admin = User.query.get(session['user_id'])
    if admin.role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    user = User.query.get_or_404(user_id)
    permissions = json.loads(user.permissions) if user.permissions else []
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'specialization': user.specialization,
        'permissions': permissions,
        'is_active': user.is_active
    })

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    admin = User.query.get(session['user_id'])
    if admin.role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    if 'email' in data:
        existing = User.query.filter(User.email == data['email'], User.id != user_id).first()
        if existing:
            return jsonify({'error': 'Email already exists'}), 400
        user.email = data['email']
    if 'is_active' in data:
        user.is_active = data['is_active']
    if 'role' in data:
        user.role = data['role']
    if 'specialization' in data:
        user.specialization = data['specialization']
    if 'permissions' in data:
        user.permissions = json.dumps(data['permissions'])
    
    db.session.commit()
    log_audit('update_user', 'user', user_id, f'Updated user {user.username}')
    return jsonify({'success': True})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    try:
        admin = User.query.get(session['user_id'])
        if admin.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user.role == 'admin':
            return jsonify({'error': 'Cannot delete admin users'}), 403
        
        username = user.username
        user.is_active = False
        user.username = f"deleted_{user_id}_{user.username}"
        user.email = f"deleted_{user_id}_{user.email}"
        db.session.commit()
        
        log_audit('delete_user', 'user', user_id, f'Deleted user {username}')
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Error deleting user {user_id}: {str(e)}')
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/incident/<int:id>/assign', methods=['POST'])
@login_required
@permission_required('assign')
def assign_incident(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    data = request.get_json() or {}
    user_id = data.get('user_id')
    
    incident.assigned_to = user_id
    if user_id:
        incident.status = 'in_progress'
    else:
        incident.status = 'open'
    
    db.session.commit()
    send_notification(incident, 'incident_assigned')
    return jsonify({'success': True})

@app.route('/api/incident/<int:id>/status', methods=['POST'])
@login_required
def update_status(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    data = request.get_json() or {}
    status = data.get('status')
    
    if user.role == 'engineer' and incident.assigned_to != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    elif user.role == 'reporter':
        return jsonify({'error': 'Permission denied'}), 403
    
    incident.status = status
    if status == 'resolved':
        incident.resolved_at = datetime.utcnow()
    
    db.session.commit()
    log_audit('update_status', 'incident', id, f'Status changed to {status}')
    send_notification(incident, 'status_changed')
    return jsonify({'success': True})

@app.route('/incident/<int:id>/comment', methods=['POST'])
@login_required
def add_comment(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    
    if user.role == 'reporter' and incident.created_by != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    elif user.role == 'engineer' and incident.assigned_to != user.id and incident.created_by != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    
    content = request.form.get('content') or request.json.get('content')
    if not content:
        return jsonify({'error': 'Comment content required'}), 400
    
    comment = Comment(
        incident_id=id,
        user_id=session['user_id'],
        content=content
    )
    db.session.add(comment)
    db.session.commit()
    
    log_audit('add_comment', 'incident', id, f'Added comment to incident #{id}')
    send_notification(incident, 'comment_added')
    
    if request.is_json:
        return jsonify({'success': True, 'comment_id': comment.id})
    else:
        flash('Comment added successfully', 'success')
        return redirect(f'/incident/{id}')

@app.route('/incident/<int:id>/work_log', methods=['POST'])
@login_required
def add_work_log(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    
    if user.role != 'engineer' or incident.assigned_to != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    work_log = WorkLog(
        incident_id=id,
        user_id=session['user_id'],
        description=data['description'],
        time_spent=float(data.get('time_spent', 0))
    )
    db.session.add(work_log)
    db.session.commit()
    
    log_audit('add_work_log', 'incident', id, f'Added work log: {data["description"]}')
    return jsonify({'success': True})

@app.route('/api/bulk-actions', methods=['POST'])
@login_required
@permission_required('bulk_actions')
def execute_bulk_actions():
    data = request.get_json()
    incident_ids = data.get('incident_ids', [])
    action = data.get('action')
    
    incidents = Incident.query.filter(Incident.id.in_(incident_ids), Incident.is_deleted == False).all()
    
    for incident in incidents:
        if action == 'assign':
            incident.assigned_to = data.get('user_id')
            incident.status = 'in_progress' if data.get('user_id') else 'open'
        elif action == 'status':
            incident.status = data.get('status')
            if data.get('status') == 'resolved':
                incident.resolved_at = datetime.utcnow()
        elif action == 'priority':
            incident.priority = data.get('priority')
        elif action == 'delete' and session.get('role') == 'admin':
            incident.is_deleted = True
    
    db.session.commit()
    log_audit(f'bulk_{action}', 'incident', None, f'Bulk {action} on {len(incidents)} incidents')
    return jsonify({'success': True})

@app.route('/api/incidents/<int:id>', methods=['DELETE'])
@login_required
def api_delete_incident(id):
    try:
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        incident = Incident.query.filter_by(id=id, is_deleted=False).first()
        if not incident:
            return jsonify({'error': 'Incident not found'}), 404
        
        incident.is_deleted = True
        db.session.commit()
        log_audit('delete_incident', 'incident', id, f'Deleted incident #{id}')
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Error deleting incident {id}: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/incident/<int:id>/upload', methods=['POST'])
@login_required
def upload_file(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    
    if user.role == 'reporter' and incident.created_by != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    elif user.role == 'engineer' and incident.assigned_to != user.id and incident.created_by != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    file.save(filepath)
    
    attachment = Attachment(
        incident_id=id,
        filename=filename,
        filepath=filepath,
        uploaded_by=session['user_id'],
        file_size=os.path.getsize(filepath)
    )
    db.session.add(attachment)
    db.session.commit()
    
    log_audit('upload_file', 'incident', id, f'Uploaded file {filename}')
    return jsonify({'success': True})

@app.route('/attachment/<int:id>')
@login_required
def download_file(id):
    attachment = Attachment.query.get_or_404(id)
    incident = Incident.query.get(attachment.incident_id)
    user = User.query.get(session['user_id'])
    
    if user.role == 'reporter' and incident.created_by != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    elif user.role == 'engineer' and incident.assigned_to != user.id and incident.created_by != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    
    return send_file(attachment.filepath, as_attachment=True, download_name=attachment.filename)

@app.route('/api/incident/<int:id>/priority', methods=['POST'])
@login_required
def update_priority(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    
    if user.role not in ['admin', 'manager']:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json() or {}
    priority = data.get('priority')
    
    incident.priority = priority
    db.session.commit()
    
    log_audit('update_priority', 'incident', id, f'Priority changed to {priority}')
    return jsonify({'success': True})

@app.route('/api/incident/<int:id>/update', methods=['POST'])
@login_required
def update_incident(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    
    if user.role not in ['admin', 'manager'] and incident.created_by != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json() or {}
    
    if 'title' in data:
        incident.title = data['title']
    if 'description' in data:
        incident.description = data['description']
    if 'priority' in data:
        incident.priority = data['priority']
    if 'severity' in data:
        incident.severity = data['severity']
    if 'category' in data:
        incident.category = data['category']
    if 'assigned_to' in data:
        incident.assigned_to = data['assigned_to']
        if data['assigned_to']:
            incident.status = 'in_progress'
    if 'status' in data:
        incident.status = data['status']
        if data['status'] == 'resolved':
            incident.resolved_at = datetime.utcnow()
    
    db.session.commit()
    
    log_audit('update_incident', 'incident', id, f'Updated incident #{id}')
    send_notification(incident, 'incident_updated')
    
    return jsonify({'success': True})

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_code=404, error_message='Page not found'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', error_code=403, error_message='Access forbidden'), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error_code=500, error_message='Internal server error'), 500

def send_notification(incident, action):
    try:
        smtp_server = os.getenv('SMTP_SERVER')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        smtp_user = os.getenv('SMTP_USER')
        smtp_pass = os.getenv('SMTP_PASS')
        
        if not all([smtp_server, smtp_user, smtp_pass]):
            logger.warning('SMTP configuration incomplete, skipping email notification')
            return
            
        creator = User.query.get(incident.created_by)
        assignee = User.query.get(incident.assigned_to) if incident.assigned_to else None
        
        recipients = [creator.email]
        if assignee and assignee.email not in recipients:
            recipients.append(assignee.email)
        
        if incident.priority == 'critical':
            managers = User.query.filter(User.role.in_(['admin', 'manager']), User.is_active == True).all()
            for manager in managers:
                if manager.email not in recipients:
                    recipients.append(manager.email)
            
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = ', '.join(recipients)
        
        priority_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
        subject = f"{priority_emoji.get(incident.priority, '')} Incident #{incident.id}: {incident.title}"
        msg['Subject'] = subject
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">
                    Incident {action.replace('_', ' ').title()}: #{incident.id}
                </h2>
                
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <h3 style="margin-top: 0; color: #2c3e50;">{incident.title}</h3>
                    <p><strong>Priority:</strong> <span style="color: {'#e74c3c' if incident.priority == 'critical' else '#f39c12' if incident.priority == 'high' else '#f1c40f' if incident.priority == 'medium' else '#27ae60'};">{incident.priority.title()}</span></p>
                    <p><strong>Severity:</strong> {incident.severity.title()}</p>
                    <p><strong>Status:</strong> {incident.status.replace('_', ' ').title()}</p>
                    <p><strong>Category:</strong> {incident.category.title()}</p>
                    <p><strong>Created by:</strong> {creator.username}</p>
                    {f'<p><strong>Assigned to:</strong> {assignee.username}</p>' if assignee else ''}
                </div>
                
                <div style="background: white; padding: 15px; border-left: 4px solid #3498db;">
                    <h4 style="margin-top: 0;">Description:</h4>
                    <p>{incident.description}</p>
                </div>
                
                <div style="margin-top: 20px; padding: 15px; background: #ecf0f1; border-radius: 5px;">
                    <p style="margin: 0; font-size: 12px; color: #7f8c8d;">
                        This is an automated notification from IncidentHub.<br>
                        Incident created: {incident.created_at.strftime('%B %d, %Y at %I:%M %p')}
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(html_body, 'html'))
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        
        logger.info(f'Email notification sent for incident #{incident.id} action: {action} to {len(recipients)} recipients')
        
    except Exception as e:
        logger.error(f'Email notification failed for incident #{incident.id}: {str(e)}')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='tarunnandigam29@gmail.com', role='admin')
            admin.set_password('admin123')
            
            manager = User(username='manager', email='tarunnandigam29@gmail.com', role='manager')
            manager.set_password('manager123')
            
            engineer = User(username='engineer', email='tarunnandigam29@gmail.com', role='engineer', specialization='devops')
            engineer.set_password('engineer123')
            
            reporter = User(username='reporter', email='tarunnandigam29@gmail.com', role='reporter')
            reporter.set_password('reporter123')
            
            db.session.add_all([admin, manager, engineer, reporter])
            db.session.commit()
    app.run(debug=True, host='0.0.0.0')