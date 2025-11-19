#!/usr/bin/env python3
"""
SLA Monitoring Script for IncidentHub
Run this script periodically (e.g., every hour) to check for SLA breaches
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db, Incident, User, send_email
from config import EMAIL_TEMPLATES
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_sla_breaches():
    """Check for SLA breaches and send alerts"""
    with app.app_context():
        try:
            # Check critical incidents older than 2 hours with no activity
            critical_incidents = Incident.query.filter(
                Incident.priority == 'critical',
                Incident.status.in_(['open', 'in_progress']),
                Incident.is_deleted == False
            ).all()
            
            breaches_found = 0
            
            for incident in critical_incidents:
                time_elapsed = datetime.utcnow() - incident.created_at
                if time_elapsed.total_seconds() > 7200:  # 2 hours
                    template = EMAIL_TEMPLATES['sla_breach']
                    
                    template_vars = {
                        'incident_id': incident.id,
                        'title': incident.title,
                        'priority': incident.priority.title(),
                        'created_time': incident.created_at.strftime('%B %d, %Y at %I:%M %p'),
                        'elapsed_time': f'{int(time_elapsed.total_seconds() / 3600)} hours',
                        'incident_url': f'http://localhost:5000/incident/{incident.id}'
                    }
                    
                    subject = template['subject'].format(**template_vars)
                    body = template['body'].format(**template_vars)
                    
                    # Send to all admins and managers
                    managers = User.query.filter(
                        User.role.in_(['admin', 'manager']), 
                        User.is_active == True
                    ).all()
                    
                    recipients = [m.email for m in managers]
                    if recipients:
                        send_email(recipients, subject, body)
                        breaches_found += 1
                        logger.info(f'SLA breach alert sent for incident #{incident.id}')
            
            if breaches_found > 0:
                logger.info(f'Found and alerted {breaches_found} SLA breaches')
            else:
                logger.info('No SLA breaches found')
                
        except Exception as e:
            logger.error(f'SLA breach check failed: {str(e)}')

if __name__ == '__main__':
    check_sla_breaches()