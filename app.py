from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from functools import wraps
import hashlib
import logging
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///incidents.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_permission(self, action, incident=None):
        permissions = {
            'admin': ['create', 'read', 'update', 'delete', 'assign', 'close'],
            'manager': ['create', 'read', 'update', 'assign', 'close'],
            'engineer': ['read', 'update_assigned'],
            'reporter': ['create', 'read_own']
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

@app.route('/dashboard')
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
    return render_template('incident_detail.html', incident=incident, users=users, comments=comments)

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
    
    if request.is_json:
        return jsonify({'success': True, 'comment_id': comment.id})
    else:
        flash('Comment added successfully', 'success')
        return redirect(url_for('view_incident', id=id))

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
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        smtp_user = os.getenv('SMTP_USER')
        smtp_pass = os.getenv('SMTP_PASS')
        
        if not all([smtp_user, smtp_pass]):
            return
            
        creator = User.query.get(incident.created_by)
        assignee = User.query.get(incident.assigned_to) if incident.assigned_to else None
        
        recipients = [creator.email]
        if assignee and assignee.email not in recipients:
            recipients.append(assignee.email)
            
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = f'Incident #{incident.id}: {incident.title}'
        
        body = f"""
        Incident {action.replace('_', ' ').title()}: #{incident.id}
        
        Title: {incident.title}
        Severity: {incident.severity.title()}
        Status: {incident.status.replace('_', ' ').title()}
        Category: {incident.category.title()}
        
        Description: {incident.description}
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"Email notification failed: {e}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default users
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('admin123')
            
            manager = User(username='manager', email='manager@example.com', role='manager')
            manager.set_password('manager123')
            
            engineer = User(username='engineer', email='engineer@example.com', role='engineer')
            engineer.set_password('engineer123')
            
            reporter = User(username='reporter', email='reporter@example.com', role='reporter')
            reporter.set_password('reporter123')
            
            db.session.add_all([admin, manager, engineer, reporter])
            db.session.commit()
            logger.info('Default users created')
    app.run(debug=True, host='0.0.0.0')