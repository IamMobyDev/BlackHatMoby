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
payment_logger = logging.getLogger('payment')

# Paystack configuration
PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY')
PAYSTACK_PUBLIC_KEY = os.getenv('PAYSTACK_PUBLIC_KEY')

# Default trial modules
DEFAULT_TRIAL_MODULES = ['getting-started', 'introduction']

# Form classes
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=25),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must start with a letter and can only contain letters, numbers, dots or underscores')
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different one.')

class CreateModuleForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    slug = StringField('Slug', validators=[
        DataRequired(),
        Regexp(r'^[a-z0-9\-]+$', message="Slug can only contain lowercase letters, numbers, and dashes")
    ])
    description = TextAreaField('Description')
    order = IntegerField('Display Order', default=0)
    trial_accessible = BooleanField('Available in Trial', default=False)
    submit = SubmitField('Create Module')

class CreateSubmoduleForm(FlaskForm):
    module_id = SelectField('Module', coerce=int, validators=[DataRequired()])
    title = StringField('Title', validators=[DataRequired()])
    slug = StringField('Slug', validators=[
        DataRequired(),
        Regexp(r'^[a-z0-9\-]+$', message="Slug can only contain lowercase letters, numbers, and dashes")
    ])
    content = TextAreaField('Content (Markdown)', validators=[DataRequired()])
    order = IntegerField('Display Order', default=0)
    submit = SubmitField('Create Submodule')

# Helper functions
def send_email_async(app, msg):
    """Send email asynchronously"""
    with app.app_context():
        try:
            mail.send(msg)
            logger.info(f"Email sent to {msg.recipients}")
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")

def send_email(subject, recipient, template, **kwargs):
    """Send an email using a template and log it"""
    try:
        msg = Message(subject, recipients=[recipient])
        msg.html = render_template(template, **kwargs)

        # Send email in background thread to avoid blocking
        threading.Thread(target=send_email_async, args=(app, msg)).start()

        # Log email in database if user_id is provided
        if 'user_id' in kwargs:
            email_log = EmailLog(
                user_id=kwargs['user_id'],
                email_type=kwargs.get('email_type', 'general'),
                subject=subject,
                recipient=recipient,
                status='sent'
            )
            db.session.add(email_log)
            db.session.commit()

        return True
    except Exception as e:
        logger.error(f"Email sending error: {str(e)}")

        # Log failed email if user_id is provided
        if 'user_id' in kwargs:
            email_log = EmailLog(
                user_id=kwargs['user_id'],
                email_type=kwargs.get('email_type', 'general'),
                subject=subject,
                recipient=recipient,
                status='failed'
            )
            db.session.add(email_log)
            db.session.commit()

        return False

def generate_verification_token():
    """Generate a unique verification token"""
    return str(uuid.uuid4())

def get_readable_amount(amount_cents):
    """Convert cents to a readable dollar amount string"""
    return f"${amount_cents/100:.2f}"

# Decorators
def login_required(view):
    """Decorator to require login for a route"""
    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapped_view

def admin_required(view):
    """Decorator to require admin rights for a route"""
    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))

        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            abort(403)

        return view(*args, **kwargs)
    return wrapped_view

def subscription_required(view):
    """Decorator to require an active subscription for a route"""
    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))

        user = User.query.get(session['user_id'])
        if not user:
            return redirect(url_for('login'))

        # Admins can access everything
        if user.role == 'admin':
            return view(*args, **kwargs)

        # Check if user has an active subscription
        if not user.has_active_subscription():
            return redirect(url_for('pricing', error="This content requires an active subscription"))

        # For specific module access, the view needs to do further checks with user.can_access_module()
        return view(*args, **kwargs)
    return wrapped_view

def verify_paystack_signature(payload, signature):
    """Verify Paystack webhook signature"""
    if not PAYSTACK_SECRET_KEY:
        payment_logger.error("Cannot verify Paystack signature: Secret key not configured")
        return False

    try:
        secret = PAYSTACK_SECRET_KEY.encode('utf-8')
        generated = hmac.new(secret, msg=payload, digestmod=hashlib.sha512).hexdigest()
        return hmac.compare_digest(generated, signature)
    except Exception as e:
        payment_logger.error(f"Signature verification error: {str(e)}")
        return False

# Routes
@app.route('/')
def index():
    """Landing page"""
    # If user is already logged in, redirect to modules or pricing based on subscription
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            if user.has_active_subscription():
                return redirect(url_for('modules'))
            else:
                return redirect(url_for('pricing'))

    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """User login page"""
    if 'user_id' in session:
        return redirect(url_for('modules'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password_hash, form.password.data):
            session.permanent = True
            session['user_id'] = user.id
            session['role'] = user.role

            # Update last login time
            user.last_login = datetime.utcnow()
            db.session.add(UserLog(user_id=user.id, action="logged in"))
            db.session.commit()

            # Redirect to the next page or modules/pricing based on subscription
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            elif user.has_active_subscription():
                return redirect(url_for('modules'))
            else:
                return redirect(url_for('pricing'))

        flash('Invalid username or password', 'error')

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    """User logout"""
    user_id = session.get('user_id')
    if user_id:
        db.session.add(UserLog(user_id=user_id, action="logged out"))
        db.session.commit()

    session.clear()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    """User registration page"""
    if 'user_id' in session:
        return redirect(url_for('modules'))

    form = RegistrationForm()
    if form.validate_on_submit():
        # Create new user
        verification_token = generate_verification_token()
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=generate_password_hash(form.password.data),
            verification_token=verification_token,
            verification_sent_at=datetime.utcnow()
        )

        db.session.add(new_user)
        db.session.add(UserLog(user_id=new_user.id, action="registered"))
        db.session.commit()

        # Send verification email
        send_email(
            subject="Verify Your Email Address",
            recipient=new_user.email,
            template='emails/verify_email.html',
            user_id=new_user.id,
            email_type='verification',
            username=new_user.username,
            verification_url=url_for('verify_email', token=verification_token, _external=True)
        )

        # Log the user in
        session.permanent = True
        session['user_id'] = new_user.id
        session['role'] = new_user.role

        flash('Account created successfully! Please check your email to verify your account.', 'success')
        return redirect(url_for('pricing'))

    return render_template('register.html', form=form)

@app.route('/verify-email/<token>')
def verify_email(token):
    """Email verification route"""
    user = User.query.filter_by(verification_token=token).first()

    if not user:
        flash('Invalid or expired verification link', 'error')
        return redirect(url_for('index'))

    # Verify user's email
    user.is_verified = True
    user.verification_token = None
    db.session.add(UserLog(user_id=user.id, action="verified email"))
    db.session.commit()

    flash('Your email has been verified! You can now fully use your account.', 'success')

    # Log the user in if not already logged in
    if 'user_id' not in session:
        session.permanent = True
        session['user_id'] = user.id
        session['role'] = user.role

    return redirect(url_for('pricing'))

@app.route('/pricing')
@login_required
def pricing():
    """Pricing page - user must be logged in to see this"""
    user = User.query.get(session['user_id'])
    plans = PaymentPlan.query.filter_by(is_active=True).order_by(PaymentPlan.price_usd).all()

    msg = request.args.get('msg')
    error = request.args.get('error')

    return render_template('pricing.html', 
                          user=user, 
                          plans=plans, 
                          msg=msg, 
                          error=error)

@app.route('/activate-trial')
@login_required
def activate_trial():
    """Activate a free trial subscription"""
    user = User.query.get(session['user_id'])

    # Check if user already has an active subscription
    if user.has_active_subscription():
        return redirect(url_for('modules'))

    # Check if user already used their trial
    if UserLog.query.filter_by(user_id=user.id, action="activated trial").first():
        flash('You have already used your free trial', 'error')
        return redirect(url_for('pricing'))

    # Get trial plan
    trial_plan = PaymentPlan.query.filter_by(slug='trial').first()
    if not trial_plan:
        flash('Trial plan not available', 'error')
        return redirect(url_for('pricing'))

    # Activate trial
    now = datetime.utcnow()
    user.subscription_status = 'trial'
    user.subscription_type = 'trial'
    user.subscription_start = now
    user.subscription_end = now + timedelta(days=trial_plan.duration_days)

    # Log the action
    db.session.add(UserLog(user_id=user.id, action="activated trial"))
    db.session.commit()

    # Send confirmation email
    send_email(
        subject="Your Free Trial Has Started",
        recipient=user.email,
        template='emails/trial_activated.html',
        user_id=user.id,
        email_type='trial_activation',
        username=user.username,
        trial_end=user.subscription_end
    )

    flash('Your free trial has been activated!', 'success')
    return redirect(url_for('modules'))

@app.route('/initiate-payment/<plan_slug>')
@login_required
@limiter.limit("5 per minute")
def initiate_payment(plan_slug):
    """Initiate a payment for a subscription plan"""
    user = User.query.get(session['user_id'])

    # Find the plan
    plan = PaymentPlan.query.filter_by(slug=plan_slug, is_active=True).first()
    if not plan:
        flash('Invalid plan selected', 'error')
        return redirect(url_for('pricing'))

    # Don't allow initiating payment for free trial
    if plan.slug == 'trial':
        return redirect(url_for('activate_trial'))

    # Create a unique reference
    reference = f"pay_{user.id}_{int(time.time())}"

    # Store the payment attempt
    payment = Payment(
        user_id=user.id,
        plan_id=plan.id,
        reference=reference,
        amount=plan.price_usd,
        status='pending',
        ip_address=request.remote_addr
    )

    db.session.add(payment)
    db.session.add(UserLog(user_id=user.id, action=f"initiated {plan.slug} payment ({reference})"))
    db.session.commit()

    payment_logger.info(f"Payment initiated: {reference} for user {user.id}, plan: {plan.slug}")

    # Render payment page with Paystack integration
    return render_template('payment.html',
                          user=user,
                          plan=plan,
                          reference=reference,
                          paystack_public_key=PAYSTACK_PUBLIC_KEY,
                          amount_usd=get_readable_amount(plan.price_usd))

@app.route('/verify-payment/<reference>', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def verify_payment(reference):
    """Verify a payment with Paystack"""
    user = User.query.get(session['user_id'])

    # Validate the reference format
    if not re.match(r'^pay_\d+_\d+$', reference):
        payment_logger.warning(f"Invalid reference format: {reference}")
        return redirect(url_for('pricing', error="Invalid payment reference"))

    # Get payment record
    payment = Payment.query.filter_by(reference=reference).first()
    if not payment:
        payment_logger.warning(f"Payment not found: {reference}")
        return redirect(url_for('pricing', error="Payment not found"))

    # Verify payment belongs to current user
    if payment.user_id != user.id:
        payment_logger.warning(f"User {user.id} attempted to verify payment of user {payment.user_id}")
        return redirect(url_for('pricing', error="Unauthorized payment verification"))

    # Check if payment already verified
    if payment.status == 'completed':
        return redirect(url_for('payment_success', reference=reference))

    # Track verification attempt
    payment.retries += 1
    verification_log = f"{datetime.utcnow()}: Verification attempt #{payment.retries}\n"

    # Verify with Paystack API
    headers = {
        'Authorization': f"Bearer {PAYSTACK_SECRET_KEY}",
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=headers,
            timeout=10
        )

        verification_log += f"API Response code: {response.status_code}\n"

        if response.status_code == 200:
            response_data = response.json()
            verification_log += f"Response data: {json.dumps(response_data)[:500]}...\n"

            if response_data['data']['status'] == 'success':
                # Get the plan
                plan = PaymentPlan.query.get(payment.plan_id)
                if not plan:
                    payment_logger.error(f"Plan not found for payment: {reference}")
                    return redirect(url_for('pricing', error="Plan not found"))

                # Inside the verify_payment function
                try:
                    # Begin transaction
                    db.session.begin()

                    # Update payment status
                    payment.status = 'completed'
                    payment.transaction_id = response_data['data']['id']
                    payment.verification_logs = (payment.verification_logs or "") + verification_log

                    # Update user subscription
                    now = datetime.utcnow()
                    user.subscription_status = 'active'
                    user.subscription_type = plan.slug
                    user.subscription_start = now

                    # Set subscription end date based on plan duration
                    if plan.duration_days:
                        user.subscription_end = now + timedelta(days=plan.duration_days)
                    else:
                        # For lifetime plans
                        user.subscription_end = None

                    # Log the action
                    db.session.add(UserLog(user_id=user.id, action=f"completed {plan.slug} payment ({reference})"))
                    db.session.commit()

                    # Send confirmation email
                    send_email(
                        subject="Payment Successful - Subscription Activated",
                        recipient=user.email,
                        template='emails/payment_success.html',
                        user_id=user.id,
                        email_type='payment_success',
                        username=user.username,
                        plan_name=plan.name,
                        subscription_end=user.subscription_end
                    )

                    payment_logger.info(f"Payment verified successfully: {reference} for user {user.id}")
                    return redirect(url_for('payment_success', reference=reference))
                except Exception as e:
                    # Roll back the transaction
                    db.session.rollback()
                    verification_log += f"Exception during payment processing: {str(e)}\n"
                    payment.verification_logs = (payment.verification_logs or "") + verification_log
                    db.session.commit()
                    payment_logger.error(f"Exception during payment processing for {reference}: {str(e)}")
                    return redirect(url_for('pricing', error="Payment processing error. Please try again or contact support"))

            else:
                verification_log += "Payment was not successful at Paystack\n"
                payment.verification_logs = (payment.verification_logs or "") + verification_log
                db.session.commit()
                payment_logger.warning(f"Payment not successful for {reference}, Paystack status: {response_data['data']['status']}")
                return redirect(url_for('pricing', error="Payment not successful. Please try again or contact support"))

        elif response.status_code == 404:
            verification_log += "Transaction was not found at Paystack\n"
            payment.verification_logs = (payment.verification_logs or "") + verification_log
            db.session.commit()
            payment_logger.warning(f"Payment not found at Paystack: {reference}")
            return redirect(url_for('pricing', error="Payment not found. Please try again or contact support"))

        else:
            verification_log += f"Unexpected response from Paystack: {response.text[:300]}...\n"
            payment.verification_logs = (payment.verification_logs or "") + verification_log
            db.session.commit()
            payment_logger.error(f"Unexpected response from Paystack for {reference}: {response.status_code} - {response.text[:300]}")
            return redirect(url_for('pricing', error="Payment verification error. Please try again or contact support"))

    except Exception as e:
        verification_log += f"Exception during verification: {str(e)}\n"
        payment.verification_logs = (payment.verification_logs or "") + verification_log
        db.session.commit()
        payment_logger.error(f"Exception during payment verification for {reference}: {str(e)}")
        return redirect(url_for('pricing', error="Payment verification error. Please try again or contact support"))
@app.route('/payment-success/<reference>')
@login_required
def payment_success(reference):
    """Payment success page"""
    user = User.query.get(session['user_id'])
    payment = Payment.query.filter_by(reference=reference, user_id=user.id).first()

    if not payment or payment.status != 'completed':
        return redirect(url_for('pricing'))

    plan = PaymentPlan.query.get(payment.plan_id)

    return render_template('payment_success.html', 
                          user=user, 
                          payment=payment, 
                          plan=plan)


@app.route('/payment-webhook', methods=['POST'])
def payment_webhook():
    """Webhook for payment notifications from Paystack"""
    # Verify the signature
    signature = request.headers.get('X-Paystack-Signature')
    if not signature:
        payment_logger.warning("Webhook called without signature")
        return jsonify(status='error'), 400

    payload = request.data
    if not verify_paystack_signature(payload, signature):
        payment_logger.warning("Invalid webhook signature")
        return jsonify(status='error'), 400

    # Parse the webhook data
    try:
        event_data = json.loads(payload)
        event = event_data.get('event')
        data = event_data.get('data', {})
        reference = data.get('reference')

        payment_logger.info(f"Webhook received: {event} for reference {reference}")

        # Handle different webhook events
        if event == 'charge.success':
            # Find payment in database
            payment = Payment.query.filter_by(reference=reference).first()
            if not payment:
                payment_logger.warning(f"Payment not found for webhook: {reference}")
                return jsonify(status='error'), 404

            # Update payment status
            payment.status = 'completed'
            payment.transaction_id = data.get('id')

            # Get user and plan
            user = User.query.get(payment.user_id)
            plan = PaymentPlan.query.get(payment.plan_id)

            if user and plan:
                # Update user subscription
                now = datetime.utcnow()
                user.subscription_status = 'active'
                user.subscription_type = plan.slug
                user.subscription_start = now

                # Set subscription end date based on plan duration
                if plan.duration_days:
                    user.subscription_end = now + timedelta(days=plan.duration_days)
                else:
                    # For lifetime plans
                    user.subscription_end = None

                # Log the action
                db.session.add(UserLog(user_id=user.id, action=f"webhook activated {plan.slug} subscription"))
                db.session.commit()

                # Send email notification
                send_email(
                    subject="Payment Confirmed - Subscription Activated",
                    recipient=user.email,
                    template='emails/payment_webhook_confirmed.html',
                    user_id=user.id,
                    email_type='payment_webhook',
                    username=user.username,
                    plan_name=plan.name,
                    subscription_end=user.subscription_end
                )

                payment_logger.info(f"Webhook processed successfully: {reference}")
                return jsonify(status='success'), 200
            else:
                payment_logger.error(f"User or plan not found for webhook: {reference}")
                return jsonify(status='error'), 404

        # Add other webhook events as needed

        # Default response for unhandled events
        return jsonify(status='success'), 200

    except Exception as e:
        payment_logger.error(f"Error processing webhook: {str(e)}")
        return jsonify(status='error'), 500


@app.route('/modules')
@login_required
def modules():
    """Display all accessible modules"""
    user = User.query.get(session['user_id'])

    # Get all modules ordered by their display order
    all_modules = Module.query.order_by(Module.order).all()

    # Filter modules based on user access
    accessible_modules = []
    for module in all_modules:
        if user.can_access_module(module.slug):
            # Calculate progress for this module
            submodule_count = len(module.submodules)
            completed_count = 0

            if submodule_count > 0:
                # Count completed submodules for this module
                for submodule in module.submodules:
                    completion = ModuleCompletion.query.filter_by(
                        user_id=user.id, 
                        submodule_id=submodule.id
                    ).first()

                    if completion:
                        completed_count += 1

                progress = int((completed_count / submodule_count) * 100)
            else:
                progress = 0

            # Add module with progress to accessible list
            accessible_modules.append({
                'module': module,
                'progress': progress,
                'completed': completed_count,
                'total': submodule_count
            })

    return render_template('modules.html', 
                          user=user, 
                          modules=accessible_modules)


@app.route('/module/<module_slug>')
@login_required
def module_detail(module_slug):
    """Display a specific module with its submodules"""
    user = User.query.get(session['user_id'])
    module = Module.query.filter_by(slug=module_slug).first_or_404()

    # Check if user can access this module
    if not user.can_access_module(module_slug):
        flash('You need an active subscription to access this module', 'error')
        return redirect(url_for('pricing'))

    # Get all submodules for this module with completion status
    submodules_with_status = []
    for submodule in module.submodules:
        completion = ModuleCompletion.query.filter_by(
            user_id=user.id, 
            submodule_id=submodule.id
        ).first()

        submodules_with_status.append({
            'submodule': submodule,
            'completed': completion is not None,
            'completed_at': completion.completed_at if completion else None
        })

    return render_template('module_detail.html', 
                          user=user, 
                          module=module,
                          submodules=submodules_with_status)


@app.route('/submodule/<module_slug>/<submodule_slug>')
@login_required
def submodule_detail(module_slug, submodule_slug):
    """Display a specific submodule content"""
    user = User.query.get(session['user_id'])
    module = Module.query.filter_by(slug=module_slug).first_or_404()

    # Check if user can access this module
    if not user.can_access_module(module_slug):
        flash('You need an active subscription to access this content', 'error')
        return redirect(url_for('pricing'))

    # Find the submodule
    submodule = Submodule.query.filter_by(module_id=module.id, slug=submodule_slug).first_or_404()

    # Get content for the submodule (from file or database)
    try:
        content_file = f"content/modules/{module_slug}/{submodule_slug}.md"
        if os.path.exists(content_file):
            with open(content_file, 'r') as f:
                content = f.read()
        else:
            content = "Content not found for this submodule."

        # Convert markdown to HTML
        html_content = markdown.markdown(content, extensions=['fenced_code', 'tables'])
    except Exception as e:
        logger.error(f"Error loading submodule content: {str(e)}")
        html_content = "<p>Error loading content. Please try again later.</p>"

    # Check if user has completed this submodule
    completion = ModuleCompletion.query.filter_by(
        user_id=user.id, 
        submodule_id=submodule.id
    ).first()

    # Get next and previous submodules for navigation
    submodules = module.submodules
    current_index = next((i for i, s in enumerate(submodules) if s.id == submodule.id), -1)

    prev_submodule = submodules[current_index - 1] if current_index > 0 else None
    next_submodule = submodules[current_index + 1] if current_index < len(submodules) - 1 else None

    return render_template('submodule_detail.html', 
                          user=user, 
                          module=module,
                          submodule=submodule,
                          content=html_content,
                          completed=completion is not None,
                          prev_submodule=prev_submodule,
                          next_submodule=next_submodule)


@app.route('/mark-complete/<int:submodule_id>', methods=['POST'])
@login_required
def mark_complete(submodule_id):
    """Mark a submodule as completed"""
    user = User.query.get(session['user_id'])
    submodule = Submodule.query.get_or_404(submodule_id)
    module = Module.query.get(submodule.module_id)

    # Check if user can access this module
    if not user.can_access_module(module.slug):
        return jsonify(success=False, error="Access denied"), 403

    # Check if already completed
    completion = ModuleCompletion.query.filter_by(
        user_id=user.id, 
        submodule_id=submodule.id
    ).first()

    if not completion:
        # Mark as completed
        completion = ModuleCompletion(
            user_id=user.id,
            submodule_id=submodule.id
        )
        db.session.add(completion)
        db.session.add(UserLog(user_id=user.id, action=f"completed submodule {submodule.id}"))
        db.session.commit()

    return jsonify(success=True)


@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    user = User.query.get(session['user_id'])

    # Get user statistics
    total_modules = Module.query.count()
    accessible_modules = 0
    completed_submodules = 0
    total_accessible_submodules = 0

    # Calculate modules and submodules statistics
    for module in Module.query.all():
        if user.can_access_module(module.slug):
            accessible_modules += 1
            for submodule in module.submodules:
                total_accessible_submodules += 1

                completion = ModuleCompletion.query.filter_by(
                    user_id=user.id, 
                    submodule_id=submodule.id
                ).first()

                if completion:
                    completed_submodules += 1

    # Calculate overall progress
    if total_accessible_submodules > 0:
        progress = int((completed_submodules / total_accessible_submodules) * 100)
    else:
        progress = 0

    # Get subscription information
    active_subscription = user.has_active_subscription()

    if active_subscription:
        if user.subscription_type == 'lifetime':
            subscription_info = "Lifetime Access"
        else:
            days_left = 0
            if user.subscription_end:
                days_left = (user.subscription_end - datetime.utcnow()).days
                if days_left < 0:
                    days_left = 0

            subscription_info = f"{user.subscription_type.capitalize()} Subscription ({days_left} days left)"
    else:
        subscription_info = "No active subscription"

    # Get recent activity
    recent_logs = UserLog.query.filter_by(user_id=user.id).order_by(UserLog.timestamp.desc()).limit(10).all()

    return render_template('profile.html', 
                          user=user,
                          progress=progress,
                          completed=completed_submodules,
                          total=total_accessible_submodules,
                          accessible_modules=accessible_modules,
                          total_modules=total_modules,
                          subscription_info=subscription_info,
                          recent_logs=recent_logs)


# Admin routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    # Get basic statistics
    total_users = User.query.count()
    active_users = User.query.filter(User.subscription_status == 'active').count()
    trial_users = User.query.filter(User.subscription_status == 'trial').count()

    # Get recent registrations
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()

    # Get recent payments
    recent_payments = Payment.query.filter_by(status='completed').order_by(Payment.updated_at.desc()).limit(10).all()

    return render_template('admin/dashboard.html',
                          total_users=total_users,
                          active_users=active_users,
                          trial_users=trial_users,
                          recent_users=recent_users,
                          recent_payments=recent_payments)


@app.route('/admin/modules')
@admin_required
def admin_modules():
    """Admin module management"""
    modules = Module.query.order_by(Module.order).all()
    form = CreateModuleForm()

    return render_template('admin/modules.html',
                          modules=modules,
                          form=form)


@app.route('/admin/modules/create', methods=['POST'])
@admin_required
def admin_create_module():
    """Create a new module"""
    form = CreateModuleForm()

    if form.validate_on_submit():
        # Check if module with this slug already exists
        existing = Module.query.filter_by(slug=form.slug.data).first()
        if existing:
            flash('A module with this slug already exists', 'error')
            return redirect(url_for('admin_modules'))

        # Create new module
        module = Module(
            title=form.title.data,
            slug=form.slug.data,
            description=form.description.data,
            order=form.order.data,
            trial_accessible=form.trial_accessible.data
        )

        db.session.add(module)
        db.session.commit()

        # Create directory for module content if it doesn't exist
        module_dir = f"content/modules/{module.slug}"
        os.makedirs(module_dir, exist_ok=True)

        flash(f'Module "{module.title}" created successfully', 'success')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'error')

    return redirect(url_for('admin_modules'))


@app.route('/admin/modules/<int:module_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_module(module_id):
    """Edit a module"""
    module = Module.query.get_or_404(module_id)

    if request.method == 'POST':
        # Update module fields
        module.title = request.form.get('title')
        module.description = request.form.get('description')
        module.order = int(request.form.get('order', 0))
        module.trial_accessible = request.form.get('trial_accessible') == 'on'

        db.session.commit()
        flash(f'Module "{module.title}" updated successfully', 'success')
        return redirect(url_for('admin_modules'))

    return render_template('admin/edit_module.html', module=module)


@app.route('/admin/submodules')
@admin_required
def admin_submodules():
    """Admin submodule management"""
    submodules = Submodule.query.join(Module).order_by(Module.order, Submodule.order).all()

    # Create form for new submodule
    form = CreateSubmoduleForm()
    form.module_id.choices = [(m.id, m.title) for m in Module.query.order_by(Module.order).all()]

    return render_template('admin/submodules.html',
                          submodules=submodules,
                          form=form)


@app.route('/admin/submodules/create', methods=['POST'])
@admin_required
def admin_create_submodule():
    """Create a new submodule"""
    form = CreateSubmoduleForm()
    form.module_id.choices = [(m.id, m.title) for m in Module.query.order_by(Module.order).all()]

    if form.validate_on_submit():
        module = Module.query.get(form.module_id.data)
        if not module:
            flash('Selected module does not exist', 'error')
            return redirect(url_for('admin_submodules'))

        # Check if submodule with this slug already exists for this module
        existing = Submodule.query.filter_by(module_id=module.id, slug=form.slug.data).first()
        if existing:
            flash('A submodule with this slug already exists for this module', 'error')
            return redirect(url_for('admin_submodules'))

        # Create new submodule
        submodule = Submodule(
            module_id=module.id,
            title=form.title.data,
            slug=form.slug.data,
            order=form.order.data
        )

        db.session.add(submodule)
        db.session.commit()

        # Save content to file
        submodule_file = f"content/modules/{module.slug}/{form.slug.data}.md"
        os.makedirs(os.path.dirname(submodule_file), exist_ok=True)

        with open(submodule_file, 'w') as f:
            f.write(form.content.data)

        flash(f'Submodule "{submodule.title}" created successfully', 'success')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'error')

    return redirect(url_for('admin_submodules'))


@app.route('/admin/submodules/<int:submodule_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_submodule(submodule_id):
    """Edit a submodule"""
    submodule = Submodule.query.get_or_404(submodule_id)
    module = Module.query.get(submodule.module_id)

    # Load content from file
    content_file = f"content/modules/{module.slug}/{submodule.slug}.md"
    try:
        if os.path.exists(content_file):
            with open(content_file, 'r') as f:
                content = f.read()
        else:
            content = ""
    except Exception as e:
        logger.error(f"Error loading submodule content: {str(e)}")
        content = ""

    if request.method == 'POST':
        # Update submodule fields
        submodule.title = request.form.get('title')
        submodule.order = int(request.form.get('order', 0))

        # Save content to file
        with open(content_file, 'w') as f:
            f.write(request.form.get('content', ''))

        db.session.commit()
        flash(f'Submodule "{submodule.title}" updated successfully', 'success')
        return redirect(url_for('admin_submodules'))

    return render_template('admin/edit_submodule.html', 
                          submodule=submodule,
                          module=module,
                          content=content)


@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin user management"""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/users/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    """Admin user detail view"""
    user = User.query.get_or_404(user_id)

    # Get user logs
    logs = UserLog.query.filter_by(user_id=user.id).order_by(UserLog.timestamp.desc()).all()

    # Get user payments
    payments = Payment.query.filter_by(user_id=user.id).order_by(Payment.created_at.desc()).all()

    # Get module progress
    module_progress = []
    for module in Module.query.order_by(Module.order).all():
        if user.can_access_module(module.slug):
            submodule_count = len(module.submodules)
            completed_count = 0

            for submodule in module.submodules:
                completion = ModuleCompletion.query.filter_by(
                    user_id=user.id, 
                    submodule_id=submodule.id
                ).first()

                if completion:
                    completed_count += 1

            if submodule_count > 0:
                progress = int((completed_count / submodule_count) * 100)
            else:
                progress = 0

            module_progress.append({
                'module': module,
                'progress': progress,
                'completed': completed_count,
                'total': submodule_count
            })

    return render_template('admin/user_detail.html',
                          user=user,
                          logs=logs,
                          payments=payments,
                          module_progress=module_progress)


@app.route('/admin/users/<int:user_id>/update', methods=['POST'])
@admin_required
def admin_update_user(user_id):
    """Update user from admin panel"""
    user = User.query.get_or_404(user_id)

    # Update user fields
    if 'role' in request.form:
        user.role = request.form.get('role')

    if 'subscription_status' in request.form:
        user.subscription_status = request.form.get('subscription_status')

    if 'subscription_type' in request.form:
        user.subscription_type = request.form.get('subscription_type')

    if 'subscription_end' in request.form:
        end_date = request.form.get('subscription_end')
        if end_date:
            user.subscription_end = datetime.fromisoformat(end_date)
        else:
            user.subscription_end = None

    db.session.add(UserLog(user_id=user.id, action=f"admin updated user profile"))
    db.session.commit()

    flash(f'User "{user.username}" updated successfully', 'success')
    return redirect(url_for('admin_user_detail', user_id=user.id))


@app.route('/admin/payments')
@admin_required
def admin_payments():
    """Admin payment management"""
    payments = Payment.query.order_by(Payment.created_at.desc()).all()
    return render_template('admin/payments.html', payments=payments)


@app.route('/admin/plans')
@admin_required
def admin_plans():
    """Admin payment plan management"""
    plans = PaymentPlan.query.order_by(PaymentPlan.price_usd).all()
    return render_template('admin/plans.html', plans=plans)


@app.route('/admin/plans/create', methods=['GET', 'POST'])
@admin_required
def admin_create_plan():
    """Create a new payment plan"""
    if request.method == 'POST':
        # Create new plan
        plan = PaymentPlan(
            name=request.form.get('name'),
            slug=request.form.get('slug'),
            description=request.form.get('description'),
            price_usd=int(float(request.form.get('price_usd', 0)) * 100),  # Convert to cents
            duration_days=int(request.form.get('duration_days', 0)) if request.form.get('duration_days') else None,
            is_active=request.form.get('is_active') == 'on'
        )

        db.session.add(plan)
        db.session.commit()

        flash(f'Plan "{plan.name}" created successfully', 'success')
        return redirect(url_for('admin_plans'))

    return render_template('admin/create_plan.html')


@app.route('/admin/plans/<int:plan_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_plan(plan_id):
    """Edit a payment plan"""
    plan = PaymentPlan.query.get_or_404(plan_id)

    if request.method == 'POST':
        # Update plan
        plan.name = request.form.get('name')
        plan.description = request.form.get('description')
        plan.price_usd = int(float(request.form.get('price_usd', 0)) * 100)  # Convert to cents

        duration_days = request.form.get('duration_days')
        plan.duration_days = int(duration_days) if duration_days else None

        plan.is_active = request.form.get('is_active') == 'on'

        db.session.commit()

        flash(f'Plan "{plan.name}" updated successfully', 'success')
        return redirect(url_for('admin_plans'))

    return render_template('admin/edit_plan.html', plan=plan)


# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}")
    return render_template('errors/500.html'), 500


# CSRF token route for AJAX requests
@app.route('/get-csrf-token')
def get_csrf_token():
    if 'user_id' not in session:
        return jsonify(error="Not authenticated"), 401

    return jsonify(csrf_token=generate_csrf())


# Custom template filters
@app.template_filter('format_date')
def format_date(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return ""
    return value.strftime(format)


@app.template_filter('format_currency')
def format_currency(value):
    if value is None:
        return "$0.00"
    # Convert cents to dollars
    return "${:.2f}".format(value / 100)


# Initialize the database and create an admin user if needed
def init_db():
    with app.app_context():
        db.create_all()

        # Check if we need to create default plans
        if PaymentPlan.query.count() == 0:
            logger.info("Creating default payment plans")

            # Create trial plan
            trial_plan = PaymentPlan(
                name="Free Trial",
                slug="trial",
                description="7-day free trial with access to limited content",
                price_usd=0,
                duration_days=7,
                is_active=True
            )

            # Create monthly plan
            monthly_plan = PaymentPlan(
                name="Monthly Access",
                slug="monthly",
                description="Full access to all content for 30 days",
                price_usd=1999,  # $19.99
                duration_days=30,
                is_active=True
            )

            # Create annual plan
            annual_plan = PaymentPlan(
                name="Annual Access",
                slug="annual",
                description="Full access to all content for 12 months",
                price_usd=9999,  # $99.99
                duration_days=365,
                is_active=True
            )

            # Create lifetime plan
            lifetime_plan = PaymentPlan(
                name="Lifetime Access",
                slug="lifetime",
                description="Unlimited access to all current and future content",
                price_usd=19999,  # $199.99
                duration_days=None,  # No expiration
                is_active=True
            )

            db.session.add_all([trial_plan, monthly_plan, annual_plan, lifetime_plan])
            db.session.commit()
            logger.info("Default payment plans created")

        # Check if we need to create an admin user
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            admin_password = os.getenv('ADMIN_INITIAL_PASSWORD', 'admin123')  # Default admin password
            admin_username = os.getenv('ADMIN_USERNAME', 'admin')
            admin_email = os.getenv('ADMIN_EMAIL', 'admin@blackmoby.com')

            logger.info(f"Creating default admin user: {admin_username}")

            # Create admin user
            admin = User(
                username=admin_username,
                email=admin_email,
                password_hash=generate_password_hash(admin_password),
                role='admin',
                is_verified=True
            )

            db.session.add(admin)
            db.session.commit()
            logger.info("Default admin user created")

        # Create default trial modules if they don't exist
        for slug in DEFAULT_TRIAL_MODULES:
            if not Module.query.filter_by(slug=slug).first():
                logger.info(f"Creating default module: {slug}")

                if slug == 'getting-started':
                    title = "Getting Started"
                    description = "Learn how to use the platform and get the most out of your learning experience."
                elif slug == 'introduction':
                    title = "Introduction"
                    description = "An introduction to the core concepts and fundamentals."
                else:
                    title = slug.replace('-', ' ').title()
                    description = f"Default {title} module."

                module = Module(
                    slug=slug,
                    title=title,
                    description=description,
                    trial_accessible=True,
                    order=DEFAULT_TRIAL_MODULES.index(slug)
                )

                db.session.add(module)
                db.session.commit()

                # Create directory for module content
                module_dir = f"content/modules/{module.slug}"
                os.makedirs(module_dir, exist_ok=True)

                # Add a welcome submodule
                welcome_submodule = Submodule(
                    module_id=module.id,
                    slug="welcome",
                    title=f"Welcome to {title}",
                    order=0
                )

                db.session.add(welcome_submodule)
                db.session.commit()

                # Create welcome content file
                welcome_file = f"{module_dir}/welcome.md"
                if not os.path.exists(welcome_file):
                    with open(welcome_file, 'w') as f:
                        f.write(f"# Welcome to {title}\n\nThis is the welcome page for the {title} module.\n\n## What You'll Learn\n\n- Point 1\n- Point 2\n- Point 3\n\n## Getting Started\n\nClick the 'Complete' button below when you're ready to move on.")

                logger.info(f"Default module created: {slug}")


# Add shell context processors for easier debugging
@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
        'Module': Module,
        'Submodule': Submodule,
        'ModuleCompletion': ModuleCompletion,
        'UserLog': UserLog,
        'PaymentPlan': PaymentPlan,
        'Payment': Payment
    }


# Setup database before first request
first_request_handled = False
@app.before_request
def before_any_request():
    global first_request_handled
    if not first_request_handled:
        first_request_handled = True
        try:
            init_db()
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")


# Add context processor for all templates
@app.context_processor
def inject_globals():
    """Add global variables to all templates"""
    return {
        'current_year': datetime.utcnow().year,
        'app_name': 'BlackMoby Learning Platform'
    }


# Run the application
if __name__ == '__main__':
    # Create content directory if it doesn't exist
    os.makedirs('content/modules', exist_ok=True)

    # Initialize the database
    init_db()

    # Start the server
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'

    app.run(host='0.0.0.0', port=port, debug=debug)