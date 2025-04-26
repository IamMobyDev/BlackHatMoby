from flask import Flask, render_template, redirect, url_for, request, session, abort, flash, send_from_directory
import markdown
import os
import re
import json
import time
import hmac
import hashlib
import requests
import logging
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from wtforms import StringField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Regexp
from models import db, User, ModuleCompletion, UserLog, Subscription, Module, Submodule, PaymentPlan
from werkzeug.utils import secure_filename
from functools import wraps

# Set up logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('blackmoby')

load_dotenv()
app = Flask(__name__)

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blackmoby.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Secrets and CSRF
app.secret_key = os.getenv('SECRET_KEY', 'development-secret-key')
app.config['WTF_CSRF_SECRET_KEY'] = os.getenv('WTF_CSRF_SECRET_KEY', 'csrf-secret-key')
app.permanent_session_lifetime = timedelta(minutes=30)

# Rate limiting & CSRF protection
limiter = Limiter(get_remote_address, app=app)
csrf = CSRFProtect(app)

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        user = User.query.get(user_id)
        if not user or user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# We're now using a local import - this will use the admin_bp from the admin.py file in the current directory
from admin_bp_setup import admin_bp

# Register blueprints - register only once!
app.register_blueprint(admin_bp)

@app.route('/')
def index():
    msg = request.args.get('msg')
    return render_template('landing.html')

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session.permanent = True
            session["user_id"] = user.id
            session["role"] = user.role

            db.session.add(UserLog(user_id=user.id, action="logged in"))
            db.session.commit()

            return redirect(url_for("admin.dashboard" if user.role == "admin" else "modules"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

@app.route('/logout')
def logout():
    user_id = session.get("user_id")
    if user_id:
        db.session.add(UserLog(user_id=user_id, action="logged out"))
        db.session.commit()

    session.clear()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if User.query.filter_by(username=username).first():
            return render_template("register.html", error="Username already exists.")

        if email and User.query.filter_by(email=email).first():
            return render_template("register.html", error="Email already in use.")

        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match.")

        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role='user'
        )
        db.session.add(new_user)
        db.session.commit()

        # Create a trial subscription
        trial_sub = Subscription(
            user_id=new_user.id,
            plan_type='trial',
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=14),
            active=True
        )
        db.session.add(trial_sub)

        db.session.add(UserLog(user_id=new_user.id, action="registered"))
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route('/modules')
def modules():
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    modules = {}
    base_path = "modules_data"
    if os.path.exists(base_path):
        for folder in os.listdir(base_path):
            folder_path = os.path.join(base_path, folder)
            if os.path.isdir(folder_path):
                submodules = []
                for filename in sorted(os.listdir(folder_path)):
                    if filename.endswith(".md"):
                        slug = filename.replace(".md", "")
                        path = os.path.join(folder_path, filename)
                        title = slug
                        try:
                            with open(path, 'r') as f:
                                first_line = f.readline().strip()
                                if first_line.startswith("# "):
                                    title = first_line[2:]
                        except:
                            pass

                        # Check completion status
                        completed = False
                        try:
                            # Try to get from database
                            module_obj = Module.query.filter_by(slug=folder).first()
                            if module_obj:
                                submodule = Submodule.query.filter(
                                    Submodule.module_id == module_obj.id,
                                    Submodule.title.like(f"%{title}%")
                                ).first()

                                if submodule:
                                    completion = ModuleCompletion.query.filter_by(
                                        user_id=user.id, 
                                        submodule_id=submodule.id
                                    ).first()

                                    if completion:
                                        completed = True
                        except Exception as e:
                            logger.error(f"Error checking completion: {str(e)}")

                        submodules.append({
                            "slug": slug,
                            "title": title,
                            "module": folder,
                            "completed": completed
                        })
                modules[folder] = submodules

    return render_template("modules.html", modules=modules, user=user)

@app.route('/module/<module>')
def view_module(module):
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    folder_path = os.path.join("modules_data", module)
    submodules = []
    content = ""
    selected_slug = None
    selected_slug_idx = None

    if os.path.isdir(folder_path):
        for filename in sorted(os.listdir(folder_path)):
            if filename.endswith(".md"):
                slug = filename.replace(".md", "")
                path = os.path.join(folder_path, filename)
                title = slug
                try:
                    with open(path, 'r') as f:
                        first_line = f.readline().strip()
                        if first_line.startswith("# "):
                            title = first_line[2:]
                except:
                    pass

                # Check completion status
                completed = False
                try:
                    # Try to get from database
                    module_obj = Module.query.filter_by(slug=module).first()
                    if module_obj:
                        submodule = Submodule.query.filter(
                            Submodule.module_id == module_obj.id,
                            Submodule.title.like(f"%{title}%")
                        ).first()

                        if submodule:
                            completion = ModuleCompletion.query.filter_by(
                                user_id=user.id, 
                                submodule_id=submodule.id
                            ).first()

                            if completion:
                                completed = True
                except Exception as e:
                    logger.error(f"Error checking completion: {str(e)}")

                submodules.append({
                    "slug": slug, 
                    "title": title,
                    "completed": completed
                })

        if submodules:
            selected_slug = submodules[0]['slug']
            selected_slug_idx = 0
            filepath = os.path.join(folder_path, f"{selected_slug}.md")
            if os.path.exists(filepath):
                with open(filepath, 'r') as file:
                    raw_md = file.read()
                    content = markdown.markdown(raw_md)

    # Check if module has lab materials
    has_lab = False
    lab_file = None
    try:
        module_obj = Module.query.filter_by(slug=module).first()
        if module_obj and module_obj.has_lab:
            has_lab = True
            lab_file = module_obj.lab_file
    except Exception as e:
        logger.error(f"Error checking lab: {str(e)}")

        # Try fallback to file check
        lab_dir = "lab_materials"
        if os.path.exists(lab_dir):
            lab_path = os.path.join(lab_dir, f"{module}.zip")
            if os.path.exists(lab_path):
                has_lab = True
                lab_file = f"{module}.zip"

    return render_template(
        "module_viewer.html", 
        module=module, 
        submodules=submodules, 
        content=content, 
        selected_slug=selected_slug, 
        selected_slug_idx=selected_slug_idx,
        user=user,
        has_lab=has_lab,
        lab_file=lab_file
    )

@app.route('/module/<module>/<slug>')
def view_submodule(module, slug):
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    folder_path = os.path.join("modules_data", module)
    filepath = os.path.join(folder_path, f"{slug}.md")
    content = "<h2>404 - Module Not Found</h2>"

    submodules = []
    if os.path.isdir(folder_path):
        for filename in sorted(os.listdir(folder_path)):
            if filename.endswith(".md"):
                sub_slug = filename.replace(".md", "")
                sub_title = sub_slug
                try:
                    with open(os.path.join(folder_path, filename), 'r') as f:
                        first_line = f.readline().strip()
                        if first_line.startswith("# "):
                            sub_title = first_line[2:]
                except:
                    pass

                # Check completion status
                completed = False
                try:
                    # Try to get from database
                    module_obj = Module.query.filter_by(slug=module).first()
                    if module_obj:
                        submodule = Submodule.query.filter(
                            Submodule.module_id == module_obj.id,
                            Submodule.title.like(f"%{sub_title}%")
                        ).first()

                        if submodule:
                            completion = ModuleCompletion.query.filter_by(
                                user_id=user.id, 
                                submodule_id=submodule.id
                            ).first()

                            if completion:
                                completed = True
                except Exception as e:
                    logger.error(f"Error checking completion: {str(e)}")

                submodules.append({
                    "slug": sub_slug, 
                    "title": sub_title,
                    "completed": completed
                })

    # Find the index of the current submodule
    selected_slug_idx = None
    for i, sub in enumerate(submodules):
        if sub['slug'] == slug:
            selected_slug_idx = i
            break

    if os.path.exists(filepath):
        with open(filepath, 'r') as file:
            raw_md = file.read()
            content = markdown.markdown(raw_md)

            # Record view (for analytics)
            try:
                module_obj = Module.query.filter_by(slug=module).first()
                if module_obj:
                    submodule = Submodule.query.filter(
                        Submodule.module_id == module_obj.id,
                        Submodule.title.like(f"%{slug.replace('-', ' ')}%")
                    ).first()

                    if submodule:
                        db.session.add(UserLog(
                            user_id=user.id, 
                            action=f"viewed module {module}/{slug}"
                        ))
                        db.session.commit()
            except Exception as e:
                logger.error(f"Error recording view: {str(e)}")

    # Check if module has lab materials
    has_lab = False
    lab_file = None
    try:
        module_obj = Module.query.filter_by(slug=module).first()
        if module_obj and module_obj.has_lab:
            has_lab = True
            lab_file = module_obj.lab_file
    except Exception as e:
        logger.error(f"Error checking lab: {str(e)}")

        # Try fallback to file check
        lab_dir = "lab_materials"
        if os.path.exists(lab_dir):
            lab_path = os.path.join(lab_dir, f"{module}.zip")
            if os.path.exists(lab_path):
                has_lab = True
                lab_file = f"{module}.zip"

    return render_template(
        "module_viewer.html", 
        module=module, 
        submodules=submodules, 
        content=content, 
        selected_slug=slug, 
        selected_slug_idx=selected_slug_idx,
        user=user,
        has_lab=has_lab,
        lab_file=lab_file
    )

@app.route('/mark-complete/<module>/<slug>', methods=['POST'])
def mark_complete(module, slug):
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    try:
        module_obj = Module.query.filter_by(slug=module).first()
        if module_obj:
            submodule = Submodule.query.filter(
                Submodule.module_id == module_obj.id,
                Submodule.title.like(f"%{slug.replace('-', ' ')}%")
            ).first()

            if submodule:
                existing = ModuleCompletion.query.filter_by(
                    user_id=user.id, 
                    submodule_id=submodule.id
                ).first()

                if not existing:
                    completion = ModuleCompletion(
                        user_id=user.id,
                        submodule_id=submodule.id
                    )
                    db.session.add(completion)
                    db.session.add(UserLog(
                        user_id=user.id, 
                        action=f"completed module {module}/{slug}"
                    ))
                    db.session.commit()
                    flash("Module marked as complete!", "success")
    except Exception as e:
        logger.error(f"Error marking complete: {str(e)}")
        flash("Error marking module as complete.", "error")

    return redirect(url_for('view_submodule', module=module, slug=slug))

@app.route('/download-lab/<module>', methods=['GET'])
def download_lab(module):
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    # Check if user has access to labs
    has_access = False
    if user.role == 'admin':
        has_access = True
    elif user.subscription:
        has_access = user.subscription.is_active() and user.subscription.plan_type != 'trial'

    if not has_access:
        flash("You need a paid subscription to access lab materials.", "error")
        return redirect(url_for('view_module', module=module))

    # Get lab file
    lab_file = None
    try:
        module_obj = Module.query.filter_by(slug=module).first()
        if module_obj and module_obj.has_lab:
            lab_file = module_obj.lab_file
    except Exception as e:
        logger.error(f"Error finding lab: {str(e)}")

    if not lab_file:
        # Try fallback to file check
        lab_dir = "lab_materials"
        lab_path = os.path.join(lab_dir, f"{module}.zip")
        if os.path.exists(lab_path):
            lab_file = f"{module}.zip"

    if lab_file:
        # Record download
        try:
            db.session.add(UserLog(
                user_id=user.id, 
                action=f"downloaded lab for {module}"
            ))
            db.session.commit()
        except Exception as e:
            logger.error(f"Error recording download: {str(e)}")

        return send_from_directory(
            'lab_materials', 
            lab_file, 
            as_attachment=True
        )

    flash("Lab materials not found.", "error")
    return redirect(url_for('view_module', module=module))

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

# Helper functions for application initialization
def init_app():
    """Initialize the application with default data"""
    with app.app_context():
        db.create_all()
        create_default_payment_plans()
        create_default_admin()
        create_default_module("getting-started", "Getting Started")
        create_default_module("introduction", "Introduction to Black Mink Labs")

# Helper functions for initial setup
def create_default_payment_plans():
    logger.info("Creating default payment plans")

    plans = [
        {
            'name': 'Free Trial',
            'slug': 'free-trial',
            'description': 'Access to basic modules for 14 days.',
            'price_usd': 0,
            'duration_days': 14
        },
        {
            'name': 'Yearly Access',
            'slug': 'yearly',
            'description': 'Full access to all modules and labs for 1 year.',
            'price_usd': 9900,  # $99.00
            'duration_days': 365
        },
        {
            'name': 'Lifetime Access',
            'slug': 'lifetime',
            'description': 'Unlimited lifetime access to all content.',
            'price_usd': 19900,  # $199.00
            'duration_days': None
        }
    ]

    for plan in plans:
        existing = PaymentPlan.query.filter_by(slug=plan['slug']).first()
        if not existing:
            new_plan = PaymentPlan(
                name=plan['name'],
                slug=plan['slug'],
                description=plan['description'],
                price_usd=plan['price_usd'],
                duration_days=plan['duration_days'],
                is_active=True
            )
            db.session.add(new_plan)

    db.session.commit()
    logger.info("Default payment plans created")

def create_default_admin():
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    admin_password = os.getenv('ADMIN_PASSWORD', 'adminpass123')

    logger.info(f"Creating default admin user: {admin_username}")

    existing_admin = User.query.filter_by(username=admin_username).first()
    if not existing_admin:
        admin_user = User(
            username=admin_username,
            email='admin@example.com',
            password_hash=generate_password_hash(admin_password),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        logger.info("Default admin user created")

def create_default_module(module_name, title):
    logger.info(f"Creating default module: {module_name}")

    module_dir = os.path.join("modules_data", module_name)
    os.makedirs(module_dir, exist_ok=True)

    # Default content
    content = f"""# {title}

Welcome to the {title} module! This is a default module created by the system.

## Getting Started

This module will help you understand the basics. Edit this content in the admin dashboard.

### Features

- Easy to understand
- Step-by-step instructions
- Practical examples
"""

    # Create intro file
    intro_file = os.path.join(module_dir, "introduction.md")
    with open(intro_file, 'w') as f:
        f.write(content)

    # Add to database
    try:
        module = Module.query.filter_by(slug=module_name).first()
        if not module:
            module = Module(
                title=title,
                slug=module_name,
                description=f"Default module for {title}",
                trial_accessible=True
            )
            db.session.add(module)
            db.session.commit()

            # Add intro submodule
            submodule = Submodule(
                module_id=module.id,
                title="Introduction",
                content=content,
                order=1
            )
            db.session.add(submodule)
            db.session.commit()
    except Exception as e:
        logger.error(f"Error creating database module: {str(e)}")

    logger.info(f"Default module created: {module_name}")

if __name__ == '__main__':
    init_app()
    app.run(debug=True, host='0.0.0.0', port=5000)