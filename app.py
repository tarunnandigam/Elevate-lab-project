from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from functools import wraps
import hashlib
import logging
import json
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///incidents.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='reporter')  # admin, manager, engineer, reporter
    specialization = db.Column(db.String(50))  # devops, network, security, database, frontend, backend
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    permissions = db.Column(db.Text)  # JSON string of permissions
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_permission(self, action, incident=None):
        permissions = {
            'admin': ['create', 'read', 'update', 'delete', 'assign', 'close', 'bulk_actions', 'user_management', 'system_settings'],
            'manager': ['create', 'read', 'update', 'assign', 'close', 'bulk_assign', 'team_management'],
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
    
    def get_team(self):
        membership = TeamMember.query.filter_by(user_id=self.id).first()
        return membership.team if membership else None

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    status = db.Column(db.String(20), nullable=False, default='open')  # open, in_progress, resolved, closed
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
    time_spent = db.Column(db.Float)  # hours
    logged_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    incident = db.relationship('Incident', backref='work_logs')
    user = db.relationship('User', backref='work_logs')

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    manager = db.relationship('User', backref='managed_teams')

class TeamMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    team = db.relationship('Team', backref='members')
    user = db.relationship('User', backref='team_memberships')

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
            logger.warning(f"Unauthorized access attempt to {request.endpoint}")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def permission_required(action):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            user = User.query.get(session['user_id'])
            if not user or not user.has_permission(action):
                logger.warning(f"Permission denied for user {user.username if user else 'Unknown'} on action {action}")
                flash('Permission denied', 'error')
                return redirect(url_for('dashboard'))
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
        return redirect(url_for('dashboard'))
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
            logger.info(f"New user registered: {username} with role {role}")
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username and password:
            user = User.query.filter_by(username=username, is_active=True).first()
            if user and user.check_password(password):
                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role
                logger.info(f"User {username} logged in successfully")
                return redirect(url_for('dashboard'))
        
        logger.warning(f"Failed login attempt for username: {username}")
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin_panel')
@login_required
def admin_panel():
    user = User.query.get(session['user_id'])
    if user.role != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    user_count = User.query.count()
    incident_count = Incident.query.filter_by(is_deleted=False).count()
    engineer_count = User.query.filter_by(role='engineer', is_active=True).count()
    
    teams = Team.query.all()
    return render_template('admin_panel.html', 
                         users=users, 
                         user_count=user_count, 
                         incident_count=incident_count, 
                         engineer_count=engineer_count,
                         teams=teams)

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
        permissions=data.get('permissions', '')
    )
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()
    
    logger.info(f'User {data["username"]} created by admin {session["username"]}')
    return jsonify({'success': True, 'user_id': new_user.id})

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    admin = User.query.get(session['user_id'])
    if admin.role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    if 'is_active' in data:
        user.is_active = data['is_active']
    if 'role' in data:
        user.role = data['role']
    if 'specialization' in data:
        user.specialization = data['specialization']
    if 'permissions' in data:
        user.permissions = data['permissions']
    
    db.session.commit()
    logger.info(f'User {user.username} updated by admin {session["username"]}')
    return jsonify({'success': True})

@app.route('/reports')
@login_required
def reports():
    user = User.query.get(session['user_id'])
    if user.role not in ['admin', 'manager']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    # Get real statistics
    total_incidents = Incident.query.filter_by(is_deleted=False).count()
    open_incidents = Incident.query.filter_by(status='open', is_deleted=False).count()
    resolved_incidents = Incident.query.filter_by(status='resolved', is_deleted=False).count()
    critical_incidents = Incident.query.filter_by(priority='critical', is_deleted=False).count()
    
    # Engineer performance
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
        'engineer_stats': engineer_stats[:10]  # Top 10
    }
    
    return render_template('reports.html', stats=stats)

@app.route('/bulk-actions')
@login_required
@permission_required('bulk_actions')
def bulk_actions():
    user = User.query.get(session['user_id'])
    incidents = Incident.query.filter_by(is_deleted=False).all()
    users = User.query.filter_by(role='engineer', is_active=True).all()
    return render_template('bulk_actions.html', incidents=incidents, users=users)

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

@app.route('/audit-logs')
@login_required
def audit_logs():
    if session.get('role') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
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
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile_settings'))
    
    return render_template('profile_settings.html', user=user)

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    
    # Filter incidents based on role permissions
    if user.role == 'reporter':
        incidents = Incident.query.filter_by(created_by=user.id, is_deleted=False).order_by(Incident.created_at.desc()).all()
    elif user.role == 'engineer':
        incidents = Incident.query.filter(
            (Incident.assigned_to == user.id) | (Incident.created_by == user.id),
            Incident.is_deleted == False
        ).order_by(Incident.created_at.desc()).all()
    else:  # admin, manager
        incidents = Incident.query.filter_by(is_deleted=False).order_by(Incident.created_at.desc()).all()
    
    # Apply filters
    status_filter = request.args.get('status')
    priority_filter = request.args.get('priority')
    assignee_filter = request.args.get('assignee')
    
    if status_filter:
        incidents = [i for i in incidents if i.status == status_filter]
    if priority_filter:
        incidents = [i for i in incidents if i.priority == priority_filter]
    if assignee_filter:
        incidents = [i for i in incidents if str(i.assigned_to) == assignee_filter]
    
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
        logger.info(f'Incident #{incident.id} created by user {session["username"]}')
        send_notification(incident, 'created')
        flash('Incident created successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('new_incident.html')

@app.route('/incident/<int:id>')
@login_required
def view_incident(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    
    # Check permissions
    if user.role == 'reporter' and incident.created_by != user.id:
        flash('Permission denied', 'error')
        return redirect(url_for('dashboard'))
    elif user.role == 'engineer' and incident.assigned_to != user.id and incident.created_by != user.id:
        flash('Permission denied', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.filter_by(is_active=True).all()
    comments = Comment.query.filter_by(incident_id=id).order_by(Comment.created_at.asc()).all()
    work_logs = WorkLog.query.filter_by(incident_id=id).order_by(WorkLog.logged_at.desc()).all()
    attachments = Attachment.query.filter_by(incident_id=id).order_by(Attachment.uploaded_at.desc()).all()
    return render_template('incident_detail.html', incident=incident, users=users, comments=comments, work_logs=work_logs, attachments=attachments)

@app.route('/incident/<int:id>/comment', methods=['POST'])
@login_required
def add_comment(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    
    # Check permissions
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
    
    logger.info(f'Comment added to incident #{id} by user {session["username"]}')
    log_audit('add_comment', 'incident', id, f'Added comment to incident #{id}')
    
    if request.is_json:
        return jsonify({'success': True, 'comment_id': comment.id})
    else:
        flash('Comment added successfully', 'success')
        return redirect(url_for('view_incident', id=id))

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

@app.route('/incident/<int:id>/upload', methods=['POST'])
@login_required
def upload_attachment(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file:
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
        
        log_audit('upload_attachment', 'incident', id, f'Uploaded file: {filename}')
        return jsonify({'success': True, 'filename': filename})

@app.route('/attachment/<int:attachment_id>')
@login_required
def download_attachment(attachment_id):
    attachment = Attachment.query.get_or_404(attachment_id)
    return send_file(attachment.filepath, as_attachment=True, download_name=attachment.filename)

# REST API Endpoints
@app.route('/api/incidents', methods=['GET'])
@login_required
def api_get_incidents():
    user = User.query.get(session['user_id'])
    
    if user.role == 'reporter':
        incidents = Incident.query.filter_by(created_by=user.id, is_deleted=False).all()
    elif user.role == 'engineer':
        incidents = Incident.query.filter(
            (Incident.assigned_to == user.id) | (Incident.created_by == user.id),
            Incident.is_deleted == False
        ).all()
    else:
        incidents = Incident.query.filter_by(is_deleted=False).all()
    
    return jsonify([{
        'id': i.id,
        'title': i.title,
        'description': i.description,
        'priority': i.priority,
        'severity': i.severity,
        'status': i.status,
        'category': i.category,
        'created_by': i.created_by,
        'assigned_to': i.assigned_to,
        'created_at': i.created_at.isoformat(),
        'updated_at': i.updated_at.isoformat()
    } for i in incidents])

@app.route('/api/incidents', methods=['POST'])
@login_required
@permission_required('create')
def api_create_incident():
    data = request.get_json()
    incident = Incident(
        title=data['title'],
        description=data['description'],
        priority=data['priority'],
        severity=data['severity'],
        category=data['category'],
        created_by=session['user_id']
    )
    db.session.add(incident)
    db.session.commit()
    logger.info(f'Incident #{incident.id} created via API by user {session["username"]}')
    send_notification(incident, 'created')
    return jsonify({'success': True, 'id': incident.id}), 201

@app.route('/api/incidents/<int:id>', methods=['GET'])
@login_required
def api_get_incident(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    
    # Check permissions
    if user.role == 'reporter' and incident.created_by != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    elif user.role == 'engineer' and incident.assigned_to != user.id and incident.created_by != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    
    return jsonify({
        'id': incident.id,
        'title': incident.title,
        'description': incident.description,
        'priority': incident.priority,
        'severity': incident.severity,
        'status': incident.status,
        'category': incident.category,
        'created_by': incident.created_by,
        'assigned_to': incident.assigned_to,
        'created_at': incident.created_at.isoformat(),
        'updated_at': incident.updated_at.isoformat(),
        'resolved_at': incident.resolved_at.isoformat() if incident.resolved_at else None
    })

@app.route('/api/incidents/<int:id>', methods=['PUT'])
@login_required
def api_update_incident(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    data = request.get_json()
    
    # Check permissions
    if user.role == 'reporter' and incident.created_by != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    elif user.role == 'engineer' and incident.assigned_to != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    
    # Update fields
    if 'title' in data:
        incident.title = data['title']
    if 'description' in data:
        incident.description = data['description']
    if 'priority' in data and user.has_permission('update'):
        incident.priority = data['priority']
    if 'severity' in data and user.has_permission('update'):
        incident.severity = data['severity']
    if 'category' in data:
        incident.category = data['category']
    
    db.session.commit()
    logger.info(f'Incident #{incident.id} updated via API by user {session["username"]}')
    return jsonify({'success': True})

@app.route('/api/incidents/<int:id>', methods=['DELETE'])
@login_required
def api_delete_incident(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    
    # Only admin and managers can delete
    if not user.has_permission('delete'):
        return jsonify({'error': 'Permission denied'}), 403
    
    # Soft delete
    incident.is_deleted = True
    db.session.commit()
    logger.info(f'Incident #{incident.id} deleted via API by user {session["username"]}')
    return jsonify({'success': True})

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
    logger.info(f'Incident #{incident.id} assigned to user {user_id} by {session["username"]}')
    send_notification(incident, 'assigned')
    return jsonify({'success': True})

@app.route('/api/incident/<int:id>/status', methods=['POST'])
@login_required
def update_status(id):
    incident = Incident.query.filter_by(id=id, is_deleted=False).first_or_404()
    user = User.query.get(session['user_id'])
    data = request.get_json() or {}
    status = data.get('status')
    
    # Check permissions for status updates
    if user.role == 'engineer' and incident.assigned_to != user.id:
        return jsonify({'error': 'Permission denied'}), 403
    elif user.role == 'reporter':
        return jsonify({'error': 'Permission denied'}), 403
    
    incident.status = status
    if status == 'resolved':
        incident.resolved_at = datetime.utcnow()
    elif status == 'closed' and not user.has_permission('close'):
        return jsonify({'error': 'Permission denied'}), 403
    
    db.session.commit()
    logger.info(f'Incident #{incident.id} status updated to {status} by {session["username"]}')
    send_notification(incident, 'status_updated')
    return jsonify({'success': True})

def send_notification(incident, action):
    try:
        # Email configuration
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
        
        # Add managers and admins for critical incidents
        if incident.priority == 'critical':
            managers = User.query.filter(User.role.in_(['admin', 'manager']), User.is_active == True).all()
            for manager in managers:
                if manager.email not in recipients:
                    recipients.append(manager.email)
            
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = ', '.join(recipients)
        
        # Enhanced subject line
        priority_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
        subject = f"{priority_emoji.get(incident.priority, '')} Incident #{incident.id}: {incident.title}"
        msg['Subject'] = subject
        
        # Enhanced email body with HTML
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

@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f'404 error: {request.url}')
    return render_template('error.html', error_code=404, error_message='Page not found'), 404

@app.errorhandler(403)
def forbidden_error(error):
    logger.warning(f'403 error: {request.url} by user {session.get("username", "Anonymous")}')
    return render_template('error.html', error_code=403, error_message='Access forbidden'), 403

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'500 error: {str(error)}')
    db.session.rollback()
    return render_template('error.html', error_code=500, error_message='Internal server error'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default users
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('admin123')
            
            manager = User(username='manager', email='manager@example.com', role='manager')
            manager.set_password('manager123')
            
            engineer = User(username='engineer', email='engineer@example.com', role='engineer', specialization='devops')
            engineer.set_password('engineer123')
            
            reporter = User(username='reporter', email='reporter@example.com', role='reporter')
            reporter.set_password('reporter123')
            
            db.session.add_all([admin, manager, engineer, reporter])
            db.session.commit()
            logger.info('Default users created')
    app.run(debug=True, host='0.0.0.0')