from flask_mail import Mail, Message
from flask import render_template, current_app
import threading
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

mail = Mail()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_email_connection(app):
    """Test SMTP connection before sending emails"""
    try:
        with app.app_context():
            server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.quit()
            logger.info("SMTP connection test successful")
            return True
    except Exception as e:
        logger.error(f"SMTP connection failed: {str(e)}")
        return False

def send_async_email(app, msg):
    """Send email asynchronously with better error handling"""
    with app.app_context():
        try:
            # Test connection first
            if not test_email_connection(app):
                logger.error("Cannot send email - SMTP connection failed")
                return False
                
            mail.send(msg)
            logger.info(f"Email sent successfully to {msg.recipients}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            
            # Fallback: Try direct SMTP sending
            try:
                send_email_direct_smtp(app, msg)
                return True
            except Exception as fallback_error:
                logger.error(f"Fallback email sending also failed: {str(fallback_error)}")
                return False

def send_email_direct_smtp(app, msg):
    """Direct SMTP sending as fallback"""
    try:
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        
        # Create message
        email_msg = MIMEMultipart()
        email_msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        email_msg['To'] = ', '.join(msg.recipients)
        email_msg['Subject'] = msg.subject
        
        if msg.html:
            email_msg.attach(MIMEText(msg.html, 'html'))
        else:
            email_msg.attach(MIMEText(msg.body, 'plain'))
            
        server.send_message(email_msg)
        server.quit()
        logger.info("Email sent successfully via direct SMTP")
        return True
    except Exception as e:
        logger.error(f"Direct SMTP sending failed: {str(e)}")
        return False

def send_otp_email(app, recipient_email, otp_code, purpose="registration"):
    """Send OTP email with enhanced error handling"""
    try:
        # Log the attempt
        logger.info(f"Attempting to send OTP {otp_code} to {recipient_email} for {purpose}")
        
        if purpose == "registration":
            subject = "Verify Your Pynex Account - OTP Required"
            template = 'email/verify_email.html'
        else:
            subject = "Reset Your Pynex Password - OTP Required"
            template = 'email/reset_password.html'
        
        html_content = render_template(
            template, 
            otp_code=otp_code, 
            email=recipient_email,
            current_year=datetime.now().year
        )
        
        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            html=html_content,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        
        # Send synchronously first for better error tracking
        try:
            with app.app_context():
                mail.send(msg)
                logger.info(f"OTP email sent successfully to {recipient_email}")
                return True
        except Exception as sync_error:
            logger.warning(f"Sync email failed, trying async: {str(sync_error)}")
            # Fallback to async
            thread = threading.Thread(target=send_async_email, args=(app, msg))
            thread.daemon = True
            thread.start()
            return True
            
    except Exception as e:
        logger.error(f"Error preparing OTP email: {str(e)}")
        return False

def send_welcome_email(app, recipient_email, name):
    """Send welcome email"""
    try:
        subject = "Welcome to Pynex Expense Tracker!"
        html_content = render_template(
            'email/welcome_email.html', 
            name=name, 
            email=recipient_email,
            current_year=datetime.now().year
        )
        
        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            html=html_content,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        
        thread = threading.Thread(target=send_async_email, args=(app, msg))
        thread.daemon = True
        thread.start()
        
        logger.info(f"Welcome email sent to {recipient_email}")
        return True
    except Exception as e:
        logger.error(f"Error preparing welcome email: {str(e)}")
        return False

def check_email_delivery(app):
    """Check if email service is working"""
    try:
        return test_email_connection(app)
    except Exception as e:
        logger.error(f"Email delivery check failed: {str(e)}")
        return False