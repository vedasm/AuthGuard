"""
Enhanced Email Service for PassGuard
Supports multiple email providers with better reliability
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import yagmail
import os

class EmailService:
    def __init__(self):
        self.smtp_servers = {
            'gmail': {
                'server': 'smtp.gmail.com',
                'port': 587,
                'security': 'tls'
            },
            'outlook': {
                'server': 'smtp-mail.outlook.com', 
                'port': 587,
                'security': 'tls'
            },
            'yahoo': {
                'server': 'smtp.mail.yahoo.com',
                'port': 587,
                'security': 'tls'
            }
        }
    
    def send_email_smtp(self, to_email, subject, body, from_email, password, provider='gmail'):
        """Send email using SMTP with better error handling"""
        try:
            config = self.smtp_servers.get(provider, self.smtp_servers['gmail'])
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = to_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Create secure connection
            context = ssl.create_default_context()
            
            with smtplib.SMTP(config['server'], config['port']) as server:
                server.starttls(context=context)
                server.login(from_email, password)
                server.send_message(msg)
            
            return True, "Email sent successfully!"
            
        except smtplib.SMTPAuthenticationError:
            return False, "Authentication failed. Check your email and password."
        except smtplib.SMTPRecipientsRefused:
            return False, "Recipient email address is invalid."
        except smtplib.SMTPServerDisconnected:
            return False, "Server disconnected. Check your internet connection."
        except Exception as e:
            return False, f"Email sending failed: {str(e)}"
    
    def send_email_yagmail(self, to_email, subject, body, from_email, password):
        """Send email using yagmail (easier setup)"""
        try:
            yag = yagmail.SMTP(from_email, password)
            yag.send(to=to_email, subject=subject, contents=body)
            return True, "Email sent successfully with yagmail!"
        except Exception as e:
            return False, f"Yagmail failed: {str(e)}"
    
    def send_email(self, to_email, subject, body, from_email, password, method='smtp', provider='gmail'):
        """Main method to send email with fallback options"""
        
        # Try yagmail first (easier)
        if method == 'yagmail':
            success, message = self.send_email_yagmail(to_email, subject, body, from_email, password)
            if success:
                return success, message
        
        # Fallback to SMTP
        success, message = self.send_email_smtp(to_email, subject, body, from_email, password, provider)
        return success, message

# Global email service instance
email_service = EmailService()