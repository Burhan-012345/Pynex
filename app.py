from flask import Flask, current_app, render_template, request, jsonify, session, redirect, url_for, flash, send_file
from models import OTP, LoginHistory, db, User, Expense
from auth import auth_bp
from email_handler import mail
from config import Config, config
from datetime import datetime, timedelta
import json
from authlib.integrations.flask_client import OAuth
import sys
import os
sys.path.append(os.path.dirname(__file__))
import csv
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors

# Add Flask-Admin imports
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
from flask_admin import AdminIndexView
from werkzeug.utils import secure_filename
from PIL import Image

# Add these imports at the top
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import base64
from io import BytesIO

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
mail.init_app(app)

# Configure upload settings
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max file size

# Only initialize OpenAI client if API key is available
openai_api_key = os.getenv('OPENAI_API_KEY')
if openai_api_key:
    from openai import OpenAI
    client = OpenAI(api_key=openai_api_key)
else:
    client = None
    print("OpenAI API key not found. Using fallback insights.")

# OAuth configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
    client_kwargs={
        'scope': 'openid email profile'
    }
)

class AdminModelView(ModelView):
    def is_accessible(self):
        try:
            user_id = session.get('user_id')
            user_role = session.get('user_role')
            
            print(f"🔐 ADMIN ACCESS CHECK:")
            print(f"   - User ID: {user_id}")
            print(f"   - User Role: {user_role}")
            print(f"   - All session keys: {list(session.keys())}")
            
            if user_role == 'admin':
                print("✅ ACCESS GRANTED - User has admin role")
                return True
            
            # If user is logged in but role missing, check database
            if user_id:
                user = User.query.get(user_id)
                if user and user.role == 'admin':
                    print("✅ ACCESS GRANTED - User is admin in database")
                    session['user_role'] = 'admin'  # Update session
                    return True
            
            print("❌ ACCESS DENIED - Not an admin")
            return False
            
        except Exception as e:
            print(f"❌ ERROR in admin access check: {e}")
            return False
    
    def inaccessible_callback(self, name, **kwargs):
        print("🚫 Redirecting to login page...")
        flash('You need administrator privileges to access this page.', 'error')
        return redirect(url_for('login_page'))

class UserModelView(AdminModelView):
    column_list = ['email', 'name', 'is_verified', 'role', 'created_at']
    column_searchable_list = ['email', 'name']
    column_filters = ['is_verified', 'role', 'created_at']
    form_columns = ['email', 'name', 'phone', 'role', 'is_verified']
    column_labels = {
        'email': 'Email',
        'name': 'Name',
        'is_verified': 'Verified',
        'role': 'Role',
        'created_at': 'Created At'
    }

class ExpenseModelView(AdminModelView):
    column_list = ['user_id', 'amount', 'category', 'date', 'created_at']
    column_searchable_list = ['category', 'description']
    column_filters = ['category', 'date', 'created_at']
    form_columns = ['user_id', 'amount', 'category', 'description', 'date']
    column_labels = {
        'user_id': 'User ID',
        'amount': 'Amount',
        'category': 'Category',
        'date': 'Date',
        'created_at': 'Created At'
    }

class OTPModelView(AdminModelView):
    column_list = ['email', 'purpose', 'created_at', 'expires_at', 'is_used']
    column_filters = ['purpose', 'is_used', 'created_at']
    can_create = False
    column_labels = {
        'email': 'Email',
        'purpose': 'Purpose',
        'created_at': 'Created At',
        'expires_at': 'Expires At',
        'is_used': 'Is Used'
    }

class LoginHistoryModelView(AdminModelView):
    column_list = ['user_id', 'ip_address', 'login_at', 'success']
    column_filters = ['success', 'login_at']
    can_create = False
    can_edit = False
    column_labels = {
        'user_id': 'User ID',
        'ip_address': 'IP Address',
        'login_at': 'Login At',
        'success': 'Success'
    }

# Admin Index View
class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return session.get('user_role') == 'admin'
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login_page'))

# Initialize Flask-Admin
admin = Admin(app, name='Pynex Admin', template_mode='bootstrap3', index_view=MyAdminIndexView())

# Add admin views
admin.add_view(UserModelView(User, db.session, name='Users'))
admin.add_view(ExpenseModelView(Expense, db.session, name='Expenses'))
admin.add_view(OTPModelView(OTP, db.session, name='OTPs'))
admin.add_view(LoginHistoryModelView(LoginHistory, db.session, name='Login History'))

# Add admin link to menu
admin.add_link(MenuLink(name='Back to Site', url='/'))

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')

# Create tables
with app.app_context():
    db.create_all()

@app.before_request
def debug_session():
    """Debug session for every request"""
    if request.endpoint and ('admin' in request.endpoint or 'debug' in request.endpoint):
        print(f"🔍 SESSION DEBUG - Endpoint: {request.endpoint}")
        print(f"🔍 Session keys: {list(session.keys())}")
        print(f"🔍 Session data: {dict(session)}")

# Google OAuth Routes
@app.route('/google-login')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/google-callback')
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            flash('Failed to get user information from Google', 'error')
            return redirect(url_for('login_page'))
        
        # Check if user exists
        user = User.query.filter_by(email=user_info['email']).first()
        
        if not user:
            # Create new user
            user = User(
                email=user_info['email'],
                name=user_info['name'],
                google_id=user_info['sub'],
                is_verified=True
            )
            db.session.add(user)
            db.session.commit()
            
            # Send welcome email
            from email_handler import send_welcome_email
            send_welcome_email(app, user_info['email'], user_info['name'])
        
        # Set session with role
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['user_name'] = user.name
        session['user_role'] = user.role  # Add this line
        session.permanent = True
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        app.logger.error(f"Google OAuth error: {e}")
        flash('Error during Google authentication', 'error')
        return redirect(url_for('login_page'))

# Add this route for the intro page
@app.route('/intro')
def intro():
    """Landing page with introduction to Pynex"""
    return render_template('dashboard/intro.html')

# Update the main route to redirect to intro instead of login
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('intro'))

# Optional: Add a route to go directly to login from intro
@app.route('/go-to-login')
def go_to_login():
    """Redirect to login page from intro"""
    return redirect(url_for('login_page'))

# Optional: Add a route to go directly to register from intro  
@app.route('/go-to-register')
def go_to_register():
    """Redirect to register page from intro"""
    return redirect(url_for('register_page'))

@app.route('/register-page')
def register_page():
    return render_template('auth/register.html')

@app.route('/login-page')
def login_page():
    return render_template('auth/login.html')

@app.route('/forgot-password-page')
def forgot_password_page():
    return render_template('auth/forgot_password.html')

@app.route('/verify-otp-page')
def verify_otp_page():
    purpose = request.args.get('purpose', 'register')
    email = request.args.get('email', '')
    return render_template('auth/verify_otp.html', purpose=purpose, email=email)

@app.route('/reset-password-page')
def reset_password_page():
    if not session.get('reset_verified'):
        return redirect(url_for('forgot_password_page'))
    return render_template('auth/reset_password.html', email=session.get('reset_email'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    # Get user expenses
    expenses = Expense.query.filter_by(user_id=session['user_id']).order_by(Expense.date.desc()).limit(5).all()
    total_expenses = db.session.query(db.func.sum(Expense.amount)).filter_by(user_id=session['user_id']).scalar() or 0
    
    return render_template('dashboard/index.html', 
                         user_name=session['user_name'],
                         expenses=expenses,
                         total_expenses=total_expenses,
                         current_date=datetime.utcnow().strftime('%Y-%m-%d'))

@app.route('/add-expense', methods=['POST'])
def add_expense():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        print(f"📝 Adding expense: {data}")  # Debug log
        
        # Validate required fields
        if not data or 'amount' not in data or 'category' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Create expense
        expense = Expense(
            user_id=session['user_id'],
            amount=float(data['amount']),
            category=data['category'],
            description=data.get('description', ''),
            date=datetime.strptime(data['date'], '%Y-%m-%d') if data.get('date') else datetime.utcnow()
        )
        
        db.session.add(expense)
        db.session.commit()
        
        print(f"✅ Expense added successfully: {expense.id}")  # Debug log
        return jsonify({'message': 'Expense added successfully', 'id': expense.id}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error adding expense: {e}")  # Debug log
        return jsonify({'error': str(e)}), 500  

@app.route('/get-expenses')
def get_expenses():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    expenses = Expense.query.filter_by(user_id=session['user_id']).order_by(Expense.date.desc()).all()
    
    expenses_data = []
    for expense in expenses:
        expenses_data.append({
            'id': expense.id,
            'amount': expense.amount,
            'category': expense.category,
            'description': expense.description,
            'date': expense.date.strftime('%Y-%m-%d'),
            'created_at': expense.created_at.strftime('%Y-%m-%d %H:%M')
        })
    
    return jsonify(expenses_data)

@app.route('/delete-expense/<expense_id>', methods=['DELETE'])
def delete_expense(expense_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    expense = Expense.query.filter_by(id=expense_id, user_id=session['user_id']).first()
    if not expense:
        return jsonify({'error': 'Expense not found'}), 404
    
    db.session.delete(expense)
    db.session.commit()
    
    return jsonify({'message': 'Expense deleted successfully'})

# Add these routes to your existing app.py

@app.route('/add-expense-page')
def add_expense_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    # Pass current date to template
    current_date = datetime.utcnow().strftime('%Y-%m-%d')
    return render_template('dashboard/add_expense.html', 
                         user_name=session['user_name'],
                         current_date=current_date)

@app.route('/all-expenses-page')
def all_expenses_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('dashboard/expenses.html', user_name=session['user_name'])

@app.route('/profile')
def profile_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login_page'))
    
    return render_template('dashboard/profile.html', 
                         user_name=user.name,
                         user=user)  # Pass the user object

@app.route('/api/user/profile', methods=['GET', 'PUT'])
def user_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if request.method == 'GET':
        return jsonify(user.to_dict())
    
    elif request.method == 'PUT':
        try:
            data = request.get_json()
            
            # Update user profile
            if 'name' in data:
                user.name = data['name'].strip()
            if 'phone' in data:
                user.phone = data['phone'].strip()
            if 'notification_email' in data:
                user.notification_email = bool(data['notification_email'])
            if 'notification_sms' in data:
                user.notification_sms = bool(data['notification_sms'])
            if 'notification_push' in data:
                user.notification_push = bool(data['notification_push'])
            if 'theme' in data:
                user.theme = data['theme']
                # Update session with theme preference
                session['user_theme'] = data['theme']
            
            user.updated_at = datetime.utcnow()
            db.session.commit()
            
            # Update session
            session['user_name'] = user.name
            
            return jsonify({
                'message': 'Profile updated successfully',
                'user': user.to_dict()
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

@app.route('/api/user/upload-avatar', methods=['POST'])
def upload_avatar():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if 'avatar' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        
        file = request.files['avatar']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            # Generate unique filename
            file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'png'
            filename = secure_filename(f"{user.id}_{int(datetime.utcnow().timestamp())}.{file_ext}")
            
            # Create avatars directory if it doesn't exist
            avatars_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'avatars')
            os.makedirs(avatars_dir, exist_ok=True)
            
            filepath = os.path.join(avatars_dir, filename)
            
            try:
                # Process image using PIL
                image = Image.open(file.stream)
                
                # Convert to RGB if necessary
                if image.mode in ('RGBA', 'P'):
                    image = image.convert('RGB')
                
                # Resize image to 200x200 while maintaining aspect ratio
                image.thumbnail((200, 200), Image.Resampling.LANCZOS)
                
                # Save processed image
                image.save(filepath, 'JPEG' if file_ext == 'jpg' else 'PNG')
                
                # Update user avatar in database
                user.avatar = filename
                db.session.commit()
                
                return jsonify({
                    'message': 'Avatar uploaded successfully',
                    'avatar_url': f"/static/uploads/avatars/{filename}"
                })
                
            except Exception as img_error:
                print(f"Image processing error: {img_error}")
                return jsonify({'error': 'Error processing image'}), 500
                
        else:
            return jsonify({'error': 'Invalid file type. Only JPG, PNG, GIF allowed.'}), 400
            
    except Exception as e:
        db.session.rollback()
        print(f"Avatar upload error: {e}")
        return jsonify({'error': str(e)}), 500

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/user/export-data')
def export_user_data():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get all user data
        expenses = Expense.query.filter_by(user_id=user.id).all()
        login_history = LoginHistory.query.filter_by(user_id=user.id).order_by(LoginHistory.login_at.desc()).all()
        
        # Prepare export data
        export_data = {
            'user_profile': user.to_dict(),
            'expenses': [expense.to_dict() for expense in expenses],
            'login_history': [history.to_dict() for history in login_history],
            'exported_at': datetime.utcnow().isoformat(),
            'total_expenses': len(expenses),
            'total_logins': len(login_history)
        }
        
        # Create JSON response
        response = jsonify(export_data)
        response.headers['Content-Disposition'] = f'attachment; filename=user_data_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
        response.headers['Content-Type'] = 'application/json'
        
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/password', methods=['PUT'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current password and new password are required'}), 400
        
        # Verify current password
        from auth import hash_password
        if user.password != hash_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 400
        
        # Validate new password
        from auth import validate_password
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Update password
        user.password = hash_password(new_password)
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'message': 'Password updated successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/stats')
def user_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Calculate statistics
        total_expenses = db.session.query(db.func.sum(Expense.amount)).filter_by(user_id=user.id).scalar() or 0
        
        # This month's expenses
        start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        this_month_expenses = db.session.query(db.func.sum(Expense.amount)).filter(
            Expense.user_id == user.id,
            Expense.date >= start_of_month
        ).scalar() or 0
        
        # Total categories used
        total_categories = db.session.query(db.func.count(db.func.distinct(Expense.category))).filter_by(user_id=user.id).scalar() or 0
        
        return jsonify({
            'total_expenses': round(total_expenses, 2),
            'this_month_expenses': round(this_month_expenses, 2),
            'total_categories': total_categories,
            'member_since': user.created_at.strftime('%b %Y')
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/expenses/chart-data')
def chart_data():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user_id = session['user_id']
        
        # Monthly data for the last 6 months
        six_months_ago = datetime.utcnow() - timedelta(days=180)
        
        monthly_expenses = db.session.query(
            db.func.strftime('%Y-%m', Expense.date).label('month'),
            db.func.sum(Expense.amount).label('total')
        ).filter(
            Expense.user_id == user_id,
            Expense.date >= six_months_ago
        ).group_by('month').order_by('month').all()
        
        monthly_data = {
            'labels': [exp.month for exp in monthly_expenses],
            'data': [float(exp.total) for exp in monthly_expenses]
        }
        
        # Category data
        category_expenses = db.session.query(
            Expense.category,
            db.func.sum(Expense.amount).label('total')
        ).filter(
            Expense.user_id == user_id
        ).group_by(Expense.category).all()
        
        category_data = {
            'labels': [exp.category for exp in category_expenses],
            'data': [float(exp.total) for exp in category_expenses]
        }
        
        return jsonify({
            'monthly': monthly_data,
            'categories': category_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/insights')
def ai_insights():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user_id = session['user_id']
        recent_expenses = Expense.query.filter_by(user_id=user_id).order_by(Expense.date.desc()).limit(50).all()
        
        if not recent_expenses:
            return jsonify({
                'insights': [{
                    'title': 'Welcome!',
                    'message': 'Start adding expenses to get personalized insights about your spending habits.',
                    'type': 'info'
                }]
            })
        
        # Use OpenAI if available, otherwise use fallback
        if client:
            try:
                # Prepare data for AI analysis
                expenses_data = []
                for expense in recent_expenses:
                    expenses_data.append({
                        'amount': expense.amount,
                        'category': expense.category,
                        'date': expense.date.strftime('%Y-%m-%d'),
                        'description': expense.description
                    })
                
                # Use OpenAI to generate insights
                prompt = f"""
                Analyze this expense data and provide 3-4 insightful observations and recommendations:
                {json.dumps(expenses_data, indent=2)}
                
                Provide the response as a JSON array with objects containing:
                - title: Short title for the insight
                - message: Detailed explanation
                - type: 'info', 'warning', or 'success'
                - suggestion: Optional actionable suggestion
                
                Focus on patterns, anomalies, and opportunities for savings.
                """
                
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are a financial advisor providing concise, actionable insights about spending patterns."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=500
                )
                
                insights_text = response.choices[0].message.content
                insights = json.loads(insights_text)
                return jsonify({'insights': insights})
                
            except Exception as e:
                print(f"OpenAI API error: {e}")
                # Fall back to smart insights
                insights = generate_smart_insights(recent_expenses)
                return jsonify({'insights': insights})
        else:
            # Use smart insights without OpenAI
            insights = generate_smart_insights(recent_expenses)
            return jsonify({'insights': insights})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_smart_insights(expenses):
    """Generate intelligent insights without external API"""
    insights = []
    
    # Calculate basic statistics
    total_spent = sum(exp.amount for exp in expenses)
    avg_daily = total_spent / 30
    today = datetime.utcnow().date()
    
    # Category analysis
    category_totals = {}
    category_counts = {}
    daily_spending = {}
    
    for exp in expenses:
        # Category totals
        category_totals[exp.category] = category_totals.get(exp.category, 0) + exp.amount
        category_counts[exp.category] = category_counts.get(exp.category, 0) + 1
        
        # Daily spending
        date_key = exp.date.strftime('%Y-%m-%d')
        daily_spending[date_key] = daily_spending.get(date_key, 0) + exp.amount
    
    # Insight 1: Top spending category
    if category_totals:
        top_category = max(category_totals.items(), key=lambda x: x[1])
        insights.append({
            'title': 'Top Spending Category',
            'message': f'You spend the most on {top_category[0]} (₹{top_category[1]:.2f})',
            'type': 'info',
            'suggestion': 'Review if this aligns with your budget goals'
        })
    
    # Insight 2: Spending frequency
    if len(expenses) > 10:
        avg_frequency = len(expenses) / 30  # expenses per day
        if avg_frequency > 3:
            insights.append({
                'title': 'Frequent Spender',
                'message': f'You make {avg_frequency:.1f} transactions per day on average',
                'type': 'warning',
                'suggestion': 'Consider consolidating smaller purchases'
            })
    
    # Insight 3: Large transactions
    large_expenses = [exp for exp in expenses if exp.amount > 1000]
    if large_expenses:
        insights.append({
            'title': 'Big Ticket Items',
            'message': f'You have {len(large_expenses)} transactions over ₹1000',
            'type': 'info',
            'suggestion': 'Plan ahead for major purchases'
        })
    
    # Insight 4: Recent spending trend
    if len(expenses) > 5:
        last_week = today - timedelta(days=7)
        recent_expenses = [exp for exp in expenses if exp.date >= last_week]
        if recent_expenses:
            recent_total = sum(exp.amount for exp in recent_expenses)
            if recent_total > total_spent * 0.4:  # More than 40% of total in last week
                insights.append({
                    'title': 'Recent Spending Spike',
                    'message': 'You spent significantly more in the last week',
                    'type': 'warning',
                    'suggestion': 'Check if this is a temporary pattern'
                })
    
    # Insight 5: Category distribution
    if len(category_totals) >= 3:
        insights.append({
            'title': 'Diverse Spending',
            'message': f'Your expenses are spread across {len(category_totals)} categories',
            'type': 'success',
            'suggestion': 'Good financial diversification'
        })
    
    # Insight 6: Daily average
    insights.append({
        'title': 'Daily Average',
        'message': f'You spend approximately ₹{avg_daily:.2f} per day',
        'type': 'info'
    })
    
    # Ensure we have at least 3 insights
    while len(insights) < 3:
        insights.append({
            'title': 'Keep Tracking',
            'message': 'Continue adding expenses to get more detailed insights',
            'type': 'info'
        })
    
    return insights[:4]  # Return max 4 insights

@app.route('/api/user/account', methods=['DELETE'])
def delete_account():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Delete user and all their expenses
        db.session.delete(user)
        db.session.commit()
        
        # Clear session after account deletion
        session.clear()
        
        return jsonify({'message': 'Account deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/expenses/<expense_id>', methods=['PUT'])
def update_expense(expense_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        expense = Expense.query.filter_by(id=expense_id, user_id=session['user_id']).first()
        if not expense:
            return jsonify({'error': 'Expense not found'}), 404
        
        data = request.get_json()
        
        # Update fields
        if 'amount' in data:
            expense.amount = float(data['amount'])
        if 'category' in data:
            expense.category = data['category']
        if 'description' in data:
            expense.description = data['description']
        if 'date' in data:
            expense.date = datetime.strptime(data['date'], '%Y-%m-%d')
        
        expense.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'message': 'Expense updated successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/recent-activity')
def recent_activity():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user_id = session['user_id']
        
        # Get recent expenses and format as activity
        recent_expenses = Expense.query.filter_by(user_id=user_id).order_by(Expense.created_at.desc()).limit(5).all()
        
        activity = []
        for expense in recent_expenses:
            activity.append({
                'title': f'Added {expense.category} expense',
                'description': f'₹{expense.amount:.2f} - {expense.description or "No description"}',
                'time': expense.created_at.strftime('%H:%M'),
                'icon': 'receipt',
                'type': 'recent'
            })
        
        return jsonify(activity)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/csv')
def export_csv():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user_id = session['user_id']
        expenses = Expense.query.filter_by(user_id=user_id).order_by(Expense.date.desc()).all()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Date', 'Amount', 'Category', 'Description', 'Created At'])
        
        # Write data
        for expense in expenses:
            writer.writerow([
                expense.date.strftime('%Y-%m-%d'),
                expense.amount,
                expense.category,
                expense.description or '',
                expense.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        output.seek(0)
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'expenses-{datetime.utcnow().strftime("%Y-%m-%d")}.csv'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/pdf')
def export_pdf():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user_id = session['user_id']
        expenses = Expense.query.filter_by(user_id=user_id).order_by(Expense.date.desc()).all()
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        
        # Set up PDF content
        p.setFont("Helvetica-Bold", 16)
        p.drawString(100, 750, "Expense Report")
        p.setFont("Helvetica", 12)
        p.drawString(100, 730, f"Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}")
        
        # Add expenses table
        y = 700
        p.setFont("Helvetica-Bold", 10)
        p.drawString(50, y, "Date")
        p.drawString(120, y, "Amount")
        p.drawString(180, y, "Category")
        p.drawString(280, y, "Description")
        
        p.setFont("Helvetica", 8)
        y -= 20
        
        total = 0
        for expense in expenses:
            if y < 100:  # New page if needed
                p.showPage()
                y = 750
                p.setFont("Helvetica-Bold", 10)
                p.drawString(50, y, "Date")
                p.drawString(120, y, "Amount")
                p.drawString(180, y, "Category")
                p.drawString(280, y, "Description")
                p.setFont("Helvetica", 8)
                y -= 20
            
            p.drawString(50, y, expense.date.strftime('%Y-%m-%d'))
            p.drawString(120, y, f"₹{expense.amount:.2f}")
            p.drawString(180, y, expense.category)
            p.drawString(280, y, expense.description or '')
            
            total += expense.amount
            y -= 15
        
        # Add total
        p.setFont("Helvetica-Bold", 12)
        p.drawString(50, y - 20, f"Total: ₹{total:.2f}")
        
        p.save()
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'expenses-report-{datetime.utcnow().strftime("%Y-%m-%d")}.pdf'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/debug-session')
def debug_session():
    """Debug route to check session data"""
    user = User.query.get(session.get('user_id')) if session.get('user_id') else None
    return jsonify({
        'session_user_id': session.get('user_id'),
        'session_user_email': session.get('user_email'),
        'session_user_name': session.get('user_name'),
        'session_user_role': session.get('user_role'),
        'db_user_role': user.role if user else 'No user',
        'has_admin_access': session.get('user_role') == 'admin',
        'all_session_keys': list(session.keys())
    })

@app.route('/admin-login-fix')
def admin_login_fix():
    """Comprehensive admin login fix"""
    try:
        admin_user = User.query.filter_by(email='admin@pynex.com').first()
        
        if not admin_user:
            return "❌ Admin user not found. Run: python create_admin.py"
        
        print(f"✅ Found admin: {admin_user.email}, ID: {admin_user.id}, Role: {admin_user.role}")
        
        # Clear any existing session
        session.clear()
        
        # Set session data
        session['user_id'] = str(admin_user.id)
        session['user_email'] = admin_user.email
        session['user_name'] = admin_user.name
        session['user_role'] = admin_user.role
        session.permanent = True
        
        # Mark session as modified
        session.modified = True
        
        print(f"✅ Session set successfully")
        print(f"✅ Session contains: {dict(session)}")
        
        # Test immediate redirect to admin
        return redirect('/admin')
        
    except Exception as e:
        return f"❌ Error: {str(e)}"
    
@app.route('/session-test')
def session_test():
    """Test if sessions are working"""
    # Set a test value
    session['test_value'] = 'Hello World'
    session['test_time'] = datetime.utcnow().isoformat()
    session.modified = True
    
    return jsonify({
        'session_id': session.sid if hasattr(session, 'sid') else 'No SID',
        'session_keys': list(session.keys()),
        'session_data': dict(session),
        'message': 'Test values set in session'
    })

# Company routes
@app.route('/about')
def about_page():
    return render_template('company/about.html')

@app.route('/careers')
def careers_page():
    return render_template('company/careers.html')

@app.route('/contact')
def contact_page():
    return render_template('company/contact.html')

@app.route('/privacy')
def privacy_page():
    return render_template('company/privacy.html')

# Resource routes
@app.route('/blog')
def blog_page():
    return render_template('resources/blog.html')

@app.route('/help-center')
def help_center_page():
    return render_template('resources/help_center.html')

@app.route('/financial-tips')
def financial_tips_page():
    return render_template('resources/financial_tips.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)