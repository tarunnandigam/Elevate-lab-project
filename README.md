# 🛡️ IncidentHub - Open Source Incident Management System

A beautiful, modern incident management portal for logging, tracking, and resolving infrastructure and application issues with role-based access control.

## ✨ Features

- **Modern UI/UX**: Beautiful gradient-based design with smooth animations
- **Role-Based Access**: Admin, Manager, and User roles with appropriate permissions
- **Incident Management**: Create, assign, track, and resolve incidents
- **Real-time Updates**: Dynamic status updates and assignments
- **Email Notifications**: SMTP-based notifications for incident updates
- **Responsive Design**: Works perfectly on desktop and mobile devices
- **Docker Support**: Easy containerization and deployment

## 🚀 Quick Start

### Local Development

1. **Clone and Setup**
   ```bash
   git clone <repository-url>
   cd open-source-management
   pip install -r requirements.txt
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your SMTP settings
   ```

3. **Run the Application**
   ```bash
   python app.py
   ```

4. **Access the Application**
   - Open http://localhost:5000
   - Login with: `admin` / `admin123`

### Docker Deployment

1. **Using Docker Compose**
   ```bash
   docker-compose up -d
   ```

2. **Using Docker**
   ```bash
   docker build -t incident-management .
   docker run -p 5000:5000 incident-management
   ```

## 🎨 Interface Preview

- **Login Page**: Sleek authentication with gradient background
- **Dashboard**: Modern stats cards with incident overview
- **Incident Creation**: Comprehensive form with guidelines
- **Incident Details**: Full incident management with quick actions

## 🔧 Configuration

### Email Notifications

Configure SMTP settings in `.env`:
```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
```

### User Roles

- **Admin**: Full system access, user management
- **Manager**: Incident assignment and resolution
- **User**: Create and view incidents

## 📊 API Endpoints

- `POST /api/incident/<id>/assign` - Assign incident to user
- `POST /api/incident/<id>/status` - Update incident status

## 🛠️ Tech Stack

- **Backend**: Python Flask
- **Database**: SQLite
- **Frontend**: Bootstrap 5, Font Awesome
- **Containerization**: Docker
- **Email**: SMTP

## 🎯 Severity Levels

- 🔴 **Critical**: System down, major outage
- 🟠 **High**: Significant impact, urgent fix needed
- 🟡 **Medium**: Moderate impact, fix within hours
- 🟢 **Low**: Minor issue, fix when convenient

## 📝 License

Open Source - Feel free to use and modify as needed.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

Built with ❤️ for efficient incident management