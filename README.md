# 🛡️ IncidentHub - Enterprise Incident Management System

A comprehensive, role-based incident management portal for logging, tracking, and resolving infrastructure and application issues with advanced features and beautiful UI.

## ✨ Key Features

### 🔐 Authentication & Authorization
- **Multi-Role System**: Admin, Manager, Engineer, Reporter roles
- **Secure Authentication**: Password hashing with Werkzeug
- **Permission-Based Access**: Granular permissions per role
- **User Registration**: Self-service signup with role selection

### 📋 Incident Management
- **Full CRUD Operations**: Create, read, update, delete (soft-delete)
- **Priority & Severity Tracking**: Dual classification system
- **Status Workflow**: Open → In Progress → Resolved → Closed
- **Assignment System**: Assign incidents to engineers
- **Advanced Filtering**: Filter by status, priority, assignee, date

### 💬 Collaboration Features
- **Timeline View**: Visual incident history
- **Comment System**: Real-time collaboration on incidents
- **Activity Tracking**: Complete audit trail

### 📧 Smart Notifications
- **HTML Email Templates**: Beautiful, responsive email notifications
- **Role-Based Alerts**: Automatic escalation for critical incidents
- **SMTP Integration**: Configurable email settings
- **Development Mode**: MailDev integration for testing

### 🎨 Modern Interface
- **Responsive Design**: Mobile-first Bootstrap 5 UI
- **Gradient Themes**: Beautiful color schemes and animations
- **Dashboard Analytics**: Real-time statistics and insights
- **Intuitive Navigation**: Role-based menu system

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Git
- Docker (optional)

### Local Development

1. **Clone Repository**
   ```bash
   git clone https://github.com/tarunnandigam/Elevate-lab-project.git
   cd Elevate-lab-project
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

4. **Run Application**
   ```bash
   python app.py
   ```

5. **Access Application**
   - URL: http://localhost:5000
   - Default Admin: `admin` / `admin123`
   - Other Users: `manager/manager123`, `engineer/engineer123`, `reporter/reporter123`

### Development with Email Testing

```bash
# Start with MailDev for email testing
docker-compose -f docker-compose.dev.yml up -d

# Access MailDev web interface at http://localhost:1080
# Configure .env to use localhost:1025 for SMTP
```

### Production Deployment

```bash
# Using Docker Compose
docker-compose up -d

# Or build manually
docker build -t incident-management .
docker run -p 5000:5000 -e SMTP_SERVER=your-smtp incident-management
```

## 🔧 Configuration

### Environment Variables

```env
# Database
SQLALCHEMY_DATABASE_URI=sqlite:///incidents.db

# Security
SECRET_KEY=your-secure-secret-key

# Email Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Application
FLASK_ENV=production
```

### User Roles & Permissions

| Role | Create | Read | Update | Assign | Delete | Close |
|------|--------|------|--------|--------|--------| ------|
| **Admin** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Manager** | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Engineer** | ❌ | ✅* | ✅* | ❌ | ❌ | ❌ |
| **Reporter** | ✅ | ✅* | ❌ | ❌ | ❌ | ❌ |

*Limited to own/assigned incidents

## 📊 REST API Documentation

### Incidents

```bash
# Get all incidents (filtered by role)
GET /api/incidents

# Create new incident
POST /api/incidents
Content-Type: application/json
{
  "title": "Database Connection Issue",
  "description": "Cannot connect to production database",
  "priority": "high",
  "severity": "critical",
  "category": "database"
}

# Get specific incident
GET /api/incidents/{id}

# Update incident
PUT /api/incidents/{id}

# Soft delete incident (Admin/Manager only)
DELETE /api/incidents/{id}

# Assign incident
POST /api/incident/{id}/assign
{"user_id": 123}

# Update status
POST /api/incident/{id}/status
{"status": "resolved"}
```

### Comments

```bash
# Add comment to incident
POST /incident/{id}/comment
{"content": "Working on this issue"}
```

## 🛠️ Technology Stack

- **Backend**: Python 3.8+, Flask 2.3+
- **Database**: SQLite (easily replaceable with PostgreSQL/MySQL)
- **Frontend**: Bootstrap 5, Font Awesome 6, Vanilla JavaScript
- **Security**: Werkzeug password hashing, session management
- **Email**: SMTP with HTML templates
- **Containerization**: Docker & Docker Compose
- **Development**: MailDev for email testing

## 🎯 Priority & Severity Matrix

### Priority Levels
- 🔴 **Critical**: Immediate action required
- 🟠 **High**: Urgent, fix within hours
- 🟡 **Medium**: Important, fix within days
- 🟢 **Low**: Minor, fix when convenient

### Severity Levels
- 🔴 **Critical**: System down, complete outage
- 🟠 **High**: Major functionality affected
- 🟡 **Medium**: Partial functionality affected
- 🟢 **Low**: Minor issue, workaround available

## 📈 Monitoring & Logging

- **Structured Logging**: JSON-formatted logs to stdout
- **Error Tracking**: Comprehensive error handling with user-friendly pages
- **Audit Trail**: Complete activity logging for compliance
- **Performance Monitoring**: Request timing and database query logging

## 🔒 Security Features

- **Password Security**: Werkzeug PBKDF2 hashing
- **Session Management**: Secure Flask sessions
- **Input Validation**: Server-side validation for all inputs
- **SQL Injection Protection**: SQLAlchemy ORM
- **XSS Protection**: Template auto-escaping
- **Role-Based Access Control**: Granular permissions

## 🚀 Production Checklist

- [ ] Set strong `SECRET_KEY`
- [ ] Configure production SMTP settings
- [ ] Set up SSL/TLS certificates
- [ ] Configure reverse proxy (nginx/Apache)
- [ ] Set up database backups
- [ ] Configure log rotation
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Configure firewall rules
- [ ] Set up automated deployments

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the API documentation

---

**Built with ❤️ for enterprise incident management**

*Elevate Lab Project - Comprehensive Incident Management Solution*