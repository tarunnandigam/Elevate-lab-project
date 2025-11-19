import os

# SMTP Configuration
SMTP_HOST = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER', 'your-email@gmail.com')
SMTP_PASSWORD = os.getenv('SMTP_PASS', 'your-app-password')
FROM_EMAIL = os.getenv('FROM_EMAIL', 'incident-system@example.com')

# Email Templates
EMAIL_TEMPLATES = {
    'incident_created': {
        'subject': '🚨 New Incident Created: #{incident_id} - {title}',
        'body': '''
New Incident Alert

Incident ID: #{incident_id}
Title: {title}
Priority: {priority}
Severity: {severity}
Category: {category}
Reporter: {reporter}

Description:
{description}

View Incident: {incident_url}

This is an automated notification from IncidentHub.
        '''
    },
    'incident_assigned': {
        'subject': '👤 Incident Assigned: #{incident_id} - {title}',
        'body': '''
You have been assigned a new incident

Incident ID: #{incident_id}
Title: {title}
Priority: {priority}
Assigned by: {assigned_by}

Description:
{description}

Please review and start working on this incident.
View Incident: {incident_url}

This is an automated notification from IncidentHub.
        '''
    },
    'status_changed': {
        'subject': '📊 Status Update: #{incident_id} - {title}',
        'body': '''
Incident Status Changed

Incident ID: #{incident_id}
Title: {title}
Previous Status: {old_status}
New Status: {new_status}
Changed by: {changed_by}

View Incident: {incident_url}

This is an automated notification from IncidentHub.
        '''
    },
    'comment_added': {
        'subject': '💬 New Comment: #{incident_id} - {title}',
        'body': '''
New Comment Added

Incident ID: #{incident_id}
Title: {title}
Comment by: {commenter}

Comment:
{comment}

View Incident: {incident_url}

This is an automated notification from IncidentHub.
        '''
    },
    'password_changed': {
        'subject': '🔐 Password Changed - IncidentHub Security Alert',
        'body': '''
Security Alert: Password Changed

Hello {username},

Your password has been successfully changed on {timestamp}.

If you did not make this change, please contact your administrator immediately.

IP Address: {ip_address}
Browser: {user_agent}

This is an automated security notification from IncidentHub.
        '''
    },
    'sla_breach': {
        'subject': '⚠️ SLA Breach Warning: #{incident_id} - {title}',
        'body': '''
SLA Breach Warning

Incident ID: #{incident_id}
Title: {title}
Priority: {priority}
Created: {created_time}
Time Elapsed: {elapsed_time}

This critical incident requires immediate attention!

View Incident: {incident_url}

This is an automated SLA alert from IncidentHub.
        '''
    }
}