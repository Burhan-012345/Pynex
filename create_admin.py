from app import app, db
from models import User
from auth import hash_password

with app.app_context():
    # Check if admin user exists
    admin_user = User.query.filter_by(email='admin@pynex.com').first()
    if not admin_user:
        admin_user = User(
            email='admin@pynex.com',
            password=hash_password('Admin123!'),  # Strong password
            name='Administrator',
            role='admin',
            is_verified=True
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully!")
        print("Email: admin@pynex.com")
        print("Password: Admin123!")
    else:
        print("Admin user already exists!")
        admin_user.role = 'admin'  # Ensure role is set to admin
        db.session.commit()
        print("Admin role confirmed!")