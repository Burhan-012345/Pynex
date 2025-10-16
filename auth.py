from flask import Blueprint, json, request, jsonify, session, redirect, url_for, flash, current_app, render_template
from models import db, User, OTP
import sys
import os
sys.path.append(os.path.dirname(__file__))
from email_handler import send_otp_email, send_welcome_email
from datetime import datetime, timedelta
import random
import hashlib
import re
import pyotp
import qrcode
import base64
from io import BytesIO

auth_bp = Blueprint('auth', __name__)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, 'Password must be at least 8 characters long'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter'
    if not re.search(r'[0-9]', password):
        return False, 'Password must contain at least one number'
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, 'Password must contain at least one special character'
    return True, ''

def generate_otp():
    return str(random.randint(100000, 999999))

def generate_2fa_secret():
    return pyotp.random_base32()

def generate_2fa_qr_code(secret, email):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="Pynex Expense Tracker")
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def generate_backup_codes(count=10):
    return [hashlib.sha256(f"{random.getrandbits(128)}".encode()).hexdigest()[:10].upper() for _ in range(count)]

@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login_page'))
    
    if request.method == 'GET':
        if user.is_2fa_enabled:
            flash('2FA is already enabled for your account', 'info')
            return redirect(url_for('dashboard'))
        
        # Generate new 2FA secret
        secret = generate_2fa_secret()
        session['2fa_secret'] = secret
        session['2fa_setup'] = True
        
        qr_code = generate_2fa_qr_code(secret, user.email)
        backup_codes = generate_backup_codes()
        session['backup_codes'] = backup_codes
        
        return render_template('auth/setup_2fa.html', 
                             qr_code=qr_code, 
                             secret=secret,
                             backup_codes=backup_codes,
                             user_name=user.name)
    
    elif request.method == 'POST':
        data = request.get_json()
        otp = data.get('otp', '').strip()
        secret = session.get('2fa_secret')
        
        if not secret:
            return jsonify({'success': False, 'error': 'Session expired. Please try again.'})
        
        totp = pyotp.TOTP(secret)
        if totp.verify(otp):
            # Enable 2FA for user
            user.is_2fa_enabled = True
            user.two_fa_secret = secret  # You'll need to add this field to your User model
            user.backup_codes = json.dumps(session.get('backup_codes', []))  # Add this field too
            
            db.session.commit()
            
            # Clear session
            session.pop('2fa_secret', None)
            session.pop('2fa_setup', None)
            session.pop('backup_codes', None)
            
            return jsonify({
                'success': True,
                'message': 'Two-factor authentication has been enabled successfully!',
                'redirect': url_for('dashboard')
            })
        else:
            return jsonify({'success': False, 'error': 'Invalid verification code. Please try again.'})

@auth_bp.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    if 'user_id' not in session or not session.get('requires_2fa'):
        return jsonify({'success': False, 'error': 'Invalid request'})
    
    data = request.get_json()
    otp = data.get('otp', '').strip()
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_2fa_enabled:
        return jsonify({'success': False, 'error': 'User not found or 2FA not enabled'})
    
    totp = pyotp.TOTP(user.two_fa_secret)
    if totp.verify(otp):
        # 2FA successful
        session['2fa_verified'] = True
        session.pop('requires_2fa', None)
        
        return jsonify({
            'success': True,
            'message': 'Verification successful!',
            'redirect': url_for('dashboard')
        })
    else:
        return jsonify({'success': False, 'error': 'Invalid verification code'})

@auth_bp.route('/verify-backup-code', methods=['POST'])
def verify_backup_code():
    if 'user_id' not in session or not session.get('requires_2fa'):
        return jsonify({'success': False, 'error': 'Invalid request'})
    
    data = request.get_json()
    backup_code = data.get('backup_code', '').strip().upper()
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_2fa_enabled:
        return jsonify({'success': False, 'error': 'User not found or 2FA not enabled'})
    
    try:
        backup_codes = json.loads(user.backup_codes) if user.backup_codes else []
        
        if backup_code in backup_codes:
            # Remove used backup code
            backup_codes.remove(backup_code)
            user.backup_codes = json.dumps(backup_codes)
            db.session.commit()
            
            # 2FA successful
            session['2fa_verified'] = True
            session.pop('requires_2fa', None)
            
            return jsonify({
                'success': True,
                'message': 'Backup code accepted!',
                'redirect': url_for('dashboard')
            })
        else:
            return jsonify({'success': False, 'error': 'Invalid backup code'})
    except Exception as e:
        current_app.logger.error(f'Backup code verification error: {str(e)}')
        return jsonify({'success': False, 'error': 'Error verifying backup code'})

@auth_bp.route('/resend-2fa', methods=['POST'])
def resend_2fa():
    # This endpoint can be used to regenerate 2FA setup if needed
    # For TOTP, we don't actually "resend" since it's time-based
    return jsonify({
        'success': True,
        'message': 'Please check your authenticator app for the current code.'
    })

@auth_bp.route('/disable-2fa', methods=['POST'])
def disable_2fa():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'})
    
    try:
        user.is_2fa_enabled = False
        user.two_fa_secret = None
        user.backup_codes = None
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Two-factor authentication has been disabled.'
        })
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Disable 2FA error: {str(e)}')
        return jsonify({'success': False, 'error': 'Failed to disable 2FA'})

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user or user.password != hash_password(password):
            return jsonify({'error': 'Invalid email or password'}), 400
        
        if not user.is_verified:
            return jsonify({'error': 'Please verify your email first'}), 400
        
        # Set session with role
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['user_name'] = user.name
        session['user_role'] = user.role  # Add this line
        session.permanent = True
        
        # Check if 2FA is enabled
        if user.is_2fa_enabled:
            session['requires_2fa'] = True
            return jsonify({
                'message': '2FA required',
                'requires_2fa': True,
                'redirect': url_for('verify_2fa_page')
            }), 200
        
        return jsonify({
            'message': 'Login successful',
            'redirect': url_for('dashboard'),
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role  # Add this line
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Login error: {str(e)}')
        return jsonify({'error': 'An error occurred during login'}), 500
    
# Add this route to app.py for the 2FA verification page
@auth_bp.route('/verify-2fa-page')
def verify_2fa_page():
    if 'user_id' not in session or not session.get('requires_2fa'):
        return redirect(url_for('login_page'))
    return render_template('auth/verify_2fa.html')

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '').strip()
        
        # Validation
        if not all([email, password, name]):
            return jsonify({'error': 'All fields are required'}), 400
        
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        is_valid_password, password_error = validate_password(password)
        if not is_valid_password:
            return jsonify({'error': password_error}), 400
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'error': 'User with this email already exists'}), 400
        
        # Cleanup expired OTPs
        OTP.cleanup_expired()
        
        # Generate OTP
        otp_code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=current_app.config['OTP_EXPIRY_MINUTES'])
        
        # Store OTP
        otp = OTP(
            email=email,
            otp_code=otp_code,
            purpose='register',
            expires_at=expires_at
        )
        db.session.add(otp)
        db.session.commit()
        
        # Store user data in session temporarily
        session['pending_user'] = {
            'email': email,
            'password': hash_password(password),
            'name': name
        }
        session['pending_user_expires'] = (datetime.utcnow() + timedelta(minutes=15)).timestamp()
        
        # Log OTP for debugging (remove in production)
        current_app.logger.info(f"Generated OTP for {email}: {otp_code}")
        print(f"DEBUG - OTP for {email}: {otp_code}")  # Remove in production
        
        # Send OTP email
        email_sent = send_otp_email(current_app, email, otp_code, 'registration')
        
        if not email_sent:
            return jsonify({
                'error': 'Failed to send OTP email. Please try again or contact support.'
            }), 500
        
        return jsonify({
            'message': 'OTP sent to your email',
            'redirect': url_for('verify_otp_page', purpose='register', email=email),
            'debug_otp': otp_code  # Remove this in production
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Registration error: {str(e)}')
        return jsonify({'error': 'An error occurred during registration'}), 500

@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        otp_code = data.get('otp', '').strip()
        purpose = data.get('purpose', 'register')
        
        if not email or not otp_code:
            return jsonify({'error': 'Email and OTP are required'}), 400
        
        # Find valid OTP
        otp_record = OTP.query.filter_by(
            email=email, 
            otp_code=otp_code, 
            purpose=purpose,
            is_used=False
        ).first()
        
        if not otp_record or not otp_record.is_valid():
            return jsonify({'error': 'Invalid or expired OTP'}), 400
        
        if purpose == 'register':
            # Check session expiration
            if ('pending_user_expires' not in session or 
                session['pending_user_expires'] < datetime.utcnow().timestamp()):
                return jsonify({'error': 'Session expired. Please register again.'}), 400
            
            pending_user = session.get('pending_user')
            if not pending_user or pending_user['email'] != email:
                return jsonify({'error': 'Session expired'}), 400
            
            # Create user
            user = User(
                email=email,
                password=pending_user['password'],
                name=pending_user['name'],
                is_verified=True
            )
            db.session.add(user)
            
            # Mark OTP as used
            otp_record.is_used = True
            
            db.session.commit()
            
            # Clear session
            session.pop('pending_user', None)
            session.pop('pending_user_expires', None)
            
            # Send welcome email
            send_welcome_email(current_app, email, pending_user['name'])
            
            return jsonify({
                'message': 'Registration successful! You can now login.',
                'redirect': url_for('login_page')
            }), 200
            
        elif purpose == 'reset':
            # Store reset token in session
            session['reset_email'] = email
            session['reset_verified'] = True
            session['reset_expires'] = (datetime.utcnow() + timedelta(minutes=15)).timestamp()
            
            # Mark OTP as used
            otp_record.is_used = True
            db.session.commit()
            
            return jsonify({
                'message': 'OTP verified successfully',
                'redirect': url_for('reset_password_page')
            }), 200
            
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'OTP verification error: {str(e)}')
        return jsonify({'error': 'An error occurred during OTP verification'}), 500

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            # Don't reveal whether email exists
            return jsonify({'message': 'If the email exists, OTP has been sent'}), 200
        
        # Cleanup expired OTPs
        OTP.cleanup_expired()
        
        # Generate OTP
        otp_code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=current_app.config['OTP_EXPIRY_MINUTES'])
        
        # Store OTP
        otp = OTP(
            email=email,
            otp_code=otp_code,
            purpose='reset',
            expires_at=expires_at
        )
        db.session.add(otp)
        db.session.commit()
        
        # Send OTP email
        send_otp_email(current_app, email, otp_code, 'reset')
        
        return jsonify({
            'message': 'If the email exists, OTP has been sent',
            'redirect': url_for('verify_otp_page', purpose='reset', email=email)
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Forgot password error: {str(e)}')
        return jsonify({'error': 'An error occurred'}), 500

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        new_password = data.get('new_password', '')
        
        if not email or not new_password:
            return jsonify({'error': 'Email and new password are required'}), 400
        
        # Check if reset is verified and not expired
        if (not session.get('reset_verified') or 
            session.get('reset_email') != email or
            session.get('reset_expires', 0) < datetime.utcnow().timestamp()):
            return jsonify({'error': 'Reset session expired or invalid'}), 400
        
        is_valid_password, password_error = validate_password(new_password)
        if not is_valid_password:
            return jsonify({'error': password_error}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Update password
        user.password = hash_password(new_password)
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Clear reset session
        session.pop('reset_email', None)
        session.pop('reset_verified', None)
        session.pop('reset_expires', None)
        
        return jsonify({
            'message': 'Password reset successful',
            'redirect': url_for('login_page')
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Reset password error: {str(e)}')
        return jsonify({'error': 'An error occurred during password reset'}), 500

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login_page'))

@auth_bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        purpose = data.get('purpose', 'register')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        # Cleanup expired OTPs
        OTP.cleanup_expired()
        
        # Generate new OTP
        otp_code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=current_app.config['OTP_EXPIRY_MINUTES'])
        
        # Store new OTP
        otp = OTP(
            email=email,
            otp_code=otp_code,
            purpose=purpose,
            expires_at=expires_at
        )
        db.session.add(otp)
        db.session.commit()
        
        # Send OTP email
        send_otp_email(current_app, email, otp_code, purpose)
        
        return jsonify({'message': 'OTP resent successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Resend OTP error: {str(e)}')
        return jsonify({'error': 'An error occurred while resending OTP'}), 500