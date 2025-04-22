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

app = Flask(__name__)
load_dotenv()

# Configure Flask app
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///instance/app.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=os.getenv('SECRET_KEY', 'dev_secret_key'),
    WTF_CSRF_SECRET_KEY=os.getenv('WTF_CSRF_SECRET_KEY', 'dev_csrf_key'),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', True),
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER')
)

# Initialize extensions
db.init_app(app)
csrf.init_app(app)
mail.init_app(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "10 per hour"]
)
csrf = CSRFProtect(app)
mail = Mail(app)
db.init_app(app)

# Authentication decorator
def auth_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Admin decorator
def admin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

#Adding login_required decorator (assumed)
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Placeholder for logger - replace with proper logging setup
payment_logger = logging.getLogger(__name__)
payment_logger.setLevel(logging.ERROR) #Set appropriate level
handler = logging.FileHandler('payment.log') #Set appropriate handler
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
payment_logger.addHandler(handler)



# Placeholder for Paystack secret key - get from environment variables
PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY')

# Import Subscription model from models
from models import User, Module, Submodule, ModuleCompletion, UserLog, Payment, PaymentPlan, Subscription, EmailLog

def get_csrf_token():
    if 'user_id' not in session:
        return jsonify(error="Not authenticated"), 401

    return jsonify(csrf_token=generate_csrf())

@app.route('/initiate-payment/<plan_slug>')
@login_required
@limiter.limit("5 per minute")
def initiate_payment(plan_slug):
    """Initialize payment for a subscription plan"""
    plan = PaymentPlan.query.filter_by(slug=plan_slug, is_active=True).first_or_404()
    user = User.query.get(session['user_id'])

    # Generate unique reference
    reference = f"sub_{user.id}_{int(time.time())}"

    # Create payment record
    payment = Payment(
        user_id=user.id,
        amount=plan.price_usd,
        plan_type=plan.slug,
        transaction_id=reference,
        status='pending'
    )
    db.session.add(payment)
    db.session.commit()

    try:
        # Initialize transaction with Paystack
        headers = {
            'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}',
            'Content-Type': 'application/json'
        }
        data = {
            'email': user.email,
            'amount': plan.price_usd * 100,  # Amount in kobo/cents
            'reference': reference,
            'callback_url': url_for('verify_payment', reference=reference, _external=True)
        }

        response = requests.post('https://api.paystack.co/transaction/initialize',
                               headers=headers,
                               json=data)

        if response.status_code == 200:
            result = response.json()
            return redirect(result['data']['authorization_url'])

        payment_logger.error(f"Paystack initialization failed: {response.text}")
        flash("Payment initialization failed. Please try again.", "error")

    except Exception as e:
        payment_logger.error(f"Payment initialization error: {str(e)}")
        flash("An error occurred. Please try again.", "error")

    return redirect(url_for('pricing'))

@app.route('/verify-payment/<reference>')
@login_required
def verify_payment(reference):
    """Verify payment status"""
    payment = Payment.query.filter_by(transaction_id=reference).first_or_404()

    try:
        # Verify transaction with Paystack
        headers = {'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}'}
        response = requests.get(f'https://api.paystack.co/transaction/verify/{reference}',
                              headers=headers)

        if response.status_code == 200:
            result = response.json()

            if result['data']['status'] == 'success':
                # Update payment status
                payment.status = 'completed'
                db.session.commit()

                # Update user subscription
                plan = PaymentPlan.query.filter_by(slug=payment.plan_type).first()
                user = User.query.get(payment.user_id)

                if plan and user:
                    subscription = Subscription(
                        user_id=user.id,
                        plan_type=plan.slug,
                        start_date=datetime.utcnow(),
                        end_date=(datetime.utcnow() + timedelta(days=plan.duration_days)) if plan.duration_days else None
                    )
                    db.session.add(subscription)
                    db.session.commit()

                    flash("Payment successful! Your subscription is now active.", "success")
                    return redirect(url_for('user_modules'))

        payment_logger.error(f"Payment verification failed: {response.text}")
        flash("Payment verification failed. Please contact support.", "error")

    except Exception as e:
        payment_logger.error(f"Payment verification error: {str(e)}")
        flash("An error occurred during verification. Please contact support.", "error")

    return redirect(url_for('pricing'))


@app.route('/admin/modules')
@admin_required
def admin_modules():
    """Admin module management"""
    modules = Module.query.order_by(Module.order).all()
    form = CreateModuleForm()
    return render_template('admin/modules.html', modules=modules, form=form)

@app.route('/admin/modules/create', methods=['POST'])
@admin_required
def create_module():
    """Create a new module"""
    form = CreateModuleForm()
    if form.validate_on_submit():
        module = Module(
            title=form.title.data,
            slug=form.slug.data,
            description=form.description.data,
            order=form.order.data,
            trial_accessible=form.trial_accessible.data
        )
        db.session.add(module)
        db.session.commit()
        flash('Module created successfully', 'success')
        return redirect(url_for('admin_modules'))
    return redirect(url_for('admin_modules'))

@app.route('/admin/modules/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_module(id):
    """Edit an existing module"""
    module = Module.query.get_or_404(id)
    if request.method == 'POST':
        module.title = request.form.get('title')
        module.description = request.form.get('description')
        module.order = int(request.form.get('order', 0))
        module.trial_accessible = bool(request.form.get('trial_accessible'))
        db.session.commit()
        flash('Module updated successfully', 'success')
        return redirect(url_for('admin_modules'))
    return render_template('edit_module.html', module=module)

@app.route('/admin/modules/<int:id>/delete', methods=['POST'])
@admin_required
def delete_module(id):
    """Delete a module"""
    module = Module.query.get_or_404(id)
    db.session.delete(module)
    db.session.commit()
    flash('Module deleted successfully', 'success')
    return redirect(url_for('admin_modules'))


class CreateModuleForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    slug = StringField('Slug', validators=[DataRequired(), Regexp(r'^[a-z0-9-]+$')])
    description = TextAreaField('Description', validators=[DataRequired()])
    order = IntegerField('Order', validators=[DataRequired()])
    trial_accessible = BooleanField('Trial Accessible')
    submit = SubmitField('Create Module')

    def validate_slug(self, field):
        if Module.query.filter_by(slug=field.data).first():
            raise ValidationError('Slug already in use.')


if __name__ == '__main__':
    app.run(debug=True)
@app.route('/pricing')
def pricing():
    """Show available payment plans"""
    plans = PaymentPlan.query.filter_by(is_active=True).order_by(PaymentPlan.price_usd).all()
    return render_template('pricing.html', plans=plans)
