
from flask import Flask, render_template, redirect, url_for, request, session, abort
import markdown
import os
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Regexp
from models import db, User, ModuleCompletion, UserLog
import logging

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Security configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-please-change')
app.config['WTF_CSRF_SECRET_KEY'] = os.getenv('WTF_CSRF_SECRET_KEY', 'csrf-key-please-change')

# Initialize extensions
db.init_app(app)
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address)

# Create tables
with app.app_context():
    db.create_all()
    
    # Create admin user if it doesn't exist
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            role='admin',
            paid=True
        )
        admin.set_password('adminpass123')
        db.session.add(admin)
        db.session.commit()
        logger.info("✅ Admin user created: admin / adminpass123")

# Import routes after db initialization
from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.modules import modules_bp

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(modules_bp)

@app.route('/')
def index():
    return render_template('landing.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)
