
from flask import Flask, render_template, redirect, url_for, request, session, abort, flash, jsonify
import markdown
import os
import re
import json
import time
import hmac
import hashlib
import requests
import logging
import uuid
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from flask_wtf.csrf import CSRFProtect
from models import db, User, Module, Submodule, ModuleCompletion, UserLog, PaymentPlan, Payment, EmailLog
import functools
from flask_mail import Mail, Message
import threading

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure Flask app
app.config.update(
    SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URI', 'sqlite:///blackmoby.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=os.getenv('SECRET_KEY', 'dev_secret_key'),
    WTF_CSRF_SECRET_KEY=os.getenv('WTF_CSRF_SECRET_KEY', 'dev_csrf_key'),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    # Email settings
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True').lower() == 'true',
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER', 'noreply@blackmoby.com')
)

# Initialize extensions
db.init_app(app)
mail = Mail(app)
limiter = Limiter(get_remote_address, app=app)
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('blackmoby')

# Import and register blueprints
from routes.admin import admin_bp
from routes.auth import auth_bp
from routes.modules import modules_bp
from routes.payment import payment_bp
from routes.main import main_bp

app.register_blueprint(admin_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(modules_bp)
app.register_blueprint(payment_bp)
app.register_blueprint(main_bp)

# Create database tables before first request
with app.app_context():
    db.create_all()
    
    # Create admin user if it doesn't exist
    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            email='admin@blackmoby.com',
            role='admin',
            is_verified=True
        )
        admin_user.set_password('adminpass123')
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Admin user created: admin / adminpass123")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
