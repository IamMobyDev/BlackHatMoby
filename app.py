
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
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, BooleanField, SelectField, IntegerField
from wtforms.validators import DataRequired, Regexp, Email, Length, EqualTo, ValidationError
from models import db, User, Module, Submodule, ModuleCompletion, UserLog, PaymentPlan, Payment, EmailLog
import functools
from flask_mail import Mail, Message
import threading

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure Flask app
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
csrf = CSRFProtect(app)
mail = Mail(app)

# Configure Flask app before creating tables
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Initialize limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Ensure instance directory exists
os.makedirs('instance', exist_ok=True)

# Create database tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('landing.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
