
from flask import Flask, render_template, redirect, url_for, request, session, abort
from dotenv import load_dotenv
import os
from datetime import timedelta
from werkzeug.security import generate_password_hash
from extensions import db, csrf, limiter, mail
from models import User, ModuleCompletion, UserLog, Payment, PaymentPlan, EmailLog, Module, Submodule

load_dotenv()
app = Flask(__name__)

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blackmoby.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secrets and CSRF
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-123')
app.config['WTF_CSRF_SECRET_KEY'] = os.getenv('WTF_CSRF_SECRET_KEY', 'csrf-key-123')
app.permanent_session_lifetime = timedelta(minutes=30)

# Initialize extensions
db.init_app(app)
csrf.init_app(app)
limiter.init_app(app)
mail.init_app(app)

# Import routes after app is created to avoid circular imports
from routes.admin import admin_bp
from routes.payment import payment_bp
from routes.auth import auth_bp
from routes.modules import modules_bp
from routes.main import main_bp

# Register blueprints
app.register_blueprint(admin_bp)
app.register_blueprint(payment_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(modules_bp)
app.register_blueprint(main_bp)

# Create database tables before first request
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Create admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('adminpass123'),
                role='admin',
                paid=True,
                is_verified=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("✅ Admin user created: admin / adminpass123")

    app.run(debug=True, host='0.0.0.0', port=3000)
