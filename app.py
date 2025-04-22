from flask import Flask, render_template, redirect, url_for, request, session, abort, flash, jsonify
import markdown
import os
import re
import json
import time
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

# Import utility functions
from utils.decorators import login_required, admin_required, subscription_required
from extensions import limiter, csrf
from utils.email import send_email
from utils.payments import verify_paystack_signature, get_readable_amount, generate_verification_token

# Or alternatively, import from utils directly if you've set up __init__.py correctly:
# from utils import login_required, admin_required, subscription_required, send_email
# from utils import verify_paystack_signature, get_readable_amount, generate_verification_token
from routes.admin import admin_bp
from routes.payment import payment_bp

# Register blueprints
app.register_blueprint(admin_bp)
app.register_blueprint(payment_bp)
