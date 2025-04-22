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
import functools
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
from flask_mail import Mail, Message
import threading

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
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from wtforms import StringField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Regexp
from models import db, User, ModuleCompletion, UserLog

load_dotenv()
app = Flask(__name__)

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blackmoby.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Secrets and CSRF
app.secret_key = os.getenv('SECRET_KEY')
app.config['WTF_CSRF_SECRET_KEY'] = os.getenv('WTF_CSRF_SECRET_KEY')
app.permanent_session_lifetime = timedelta(minutes=30)

# Rate limiting & CSRF protection
limiter = Limiter(get_remote_address, app=app)
csrf = CSRFProtect(app)


@app.route('/')
def index():
    msg = request.args.get('msg')
    return render_template('landing.html', msg=msg)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session.permanent = True
            session["user_id"] = user.id
            session["role"] = user.role

            db.session.add(UserLog(user_id=user.id, action="logged in"))
            db.session.commit()

            print(f"User role: {user.role}")  # Debug print
            if user.role == "admin":
                return redirect(url_for("dashboard"))
            else:
                return redirect(url_for("modules"))

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

        new_user = User(username=username,
                        email=email,
                        password_hash=generate_password_hash(password),
                        role='user')
        db.session.add(new_user)
        db.session.commit()

        db.session.add(UserLog(user_id=new_user.id, action="registered"))
        db.session.commit()

        return redirect(url_for("login", msg="Registration successful. Please log in."))

    return render_template("register.html")


class CreateModuleForm(FlaskForm):
    module = StringField('Module (Folder)', validators=[DataRequired(), Regexp(r'^[A-Za-z0-9\- ]+$', message="Only letters, numbers, spaces, and dashes allowed.")])
    slug = StringField('Submodule Slug (Filename)', validators=[DataRequired(), Regexp(r'^[A-Za-z0-9\-]+$', message="Only letters, numbers, and dashes allowed.")])
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content (Markdown)', validators=[DataRequired()])
    submit = SubmitField('Create Module')

@app.route('/modules')
def user_modules():
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    base_path = "modules_data"
    module_folders = []
    if os.path.exists(base_path):
        for folder in os.listdir(base_path):
            folder_path = os.path.join(base_path, folder)
            if os.path.isdir(folder_path):
                module_folders.append(folder)

    return render_template("user_modules.html", modules=module_folders, user=user)

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
    selected_slug_idx = None  # Initialize the variable

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
                submodules.append({"slug": slug, "title": title})

        if submodules:
            selected_slug = submodules[0]['slug']
            selected_slug_idx = 0  # Set to first item index
            filepath = os.path.join(folder_path, f"{selected_slug}.md")
            if os.path.exists(filepath):
                with open(filepath, 'r') as file:
                    raw_md = file.read()
                    content = markdown.markdown(raw_md)

    return render_template("module_viewer.html", 
                          module=module, 
                          submodules=submodules, 
                          content=content, 
                          selected_slug=selected_slug, 
                          selected_slug_idx=selected_slug_idx,  # Add this line
                          user=user)
## Admin routes


## Create Module
@app.route('/create-module', methods=['GET', 'POST'])
def create_module():
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user or user.role != 'admin':
        abort(403)

    form = CreateModuleForm()
    
    # Get list of existing modules
    existing_modules = []
    base_path = "modules_data"
    if os.path.exists(base_path):
        for folder in os.listdir(base_path):
            folder_path = os.path.join(base_path, folder)
            if os.path.isdir(folder_path):
                existing_modules.append(folder)

    if form.validate_on_submit():
        module_option = request.form.get('module_option', 'new')
        
        # Handle module selection based on radio button choice
        if module_option == 'new':
            new_module_name = request.form.get('new_module', '').strip()
            if not new_module_name:
                return render_template('admin_create_module.html', 
                                      form=form, 
                                      existing_modules=existing_modules,
                                      error="New module name is required when creating a new module.")
                
            module = new_module_name.lower().replace(' ', '-')
            msg_prefix = f"Module folder '{module}' created! "
        else:  # existing module selected
            module = request.form.get('existing_module', '').strip()
            if not module:
                return render_template('admin_create_module.html', 
                                      form=form, 
                                      existing_modules=existing_modules,
                                      error="Please select an existing module.")
            msg_prefix = ""
        
        slug = form.slug.data.strip().lower()
        title = form.title.data.strip()
        content = form.content.data

        folder_path = f"modules_data/{module}"
        os.makedirs(folder_path, exist_ok=True)
        
        filepath = f"{folder_path}/{slug}.md"
        if os.path.exists(filepath):
            return render_template('admin_create_module.html', 
                                  form=form, 
                                  existing_modules=existing_modules,
                                  error=f"Submodule '{slug}' already exists in module '{module}'.")

        uploaded_files = request.files.getlist("images")
        os.makedirs("static/uploads", exist_ok=True)

        for uploaded_file in uploaded_files:
            if uploaded_file and uploaded_file.filename != "":
                upload_path = os.path.join("static/uploads", uploaded_file.filename)
                uploaded_file.save(upload_path)
                content += f"\n\n![image](/static/uploads/{uploaded_file.filename})"

        with open(filepath, 'w') as f:
            f.write(f"# {title}\n\n" + content)

        return render_template('admin_create_module.html', 
                              form=form, 
                              existing_modules=existing_modules,
                              msg=f"{msg_prefix}Submodule '{slug}' created under '{module}'!")

    return render_template('admin_create_module.html', 
                         form=form, 
                         existing_modules=existing_modules)
## Dashboard
@app.route('/dashboard')
@admin_required
def dashboard():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for('login'))
        
    user = User.query.get(user_id)
    if not user or user.role != 'admin':
        return redirect(url_for('login'))

    modules = {}
    base_path = "modules_data"
    if os.path.exists(base_path):
        for folder in os.listdir(base_path):
            folder_path = os.path.join(base_path, folder)
            if os.path.isdir(folder_path):
                submodules = []
                for filename in os.listdir(folder_path):
                    if filename.endswith(".md"):
                        slug = filename.replace(".md", "")
                        submodules.append({
                            "slug": slug,
                            "filename": filename,
                            "module": folder
                        })
                modules[folder] = submodules

    print(f"User role: {user.role}")  # Debug print
    print(f"Modules: {modules}")  # Debug print
    msg = request.args.get("msg")
    error = request.args.get("error")
    return render_template("admin_dashboard.html", modules=modules, msg=msg, error=error, user=user)


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
                submodules.append({"slug": sub_slug, "title": sub_title})
    
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
    
    return render_template(
        "module_viewer.html", 
        module=module, 
        submodules=submodules, 
        content=content, 
        selected_slug=slug, 
        selected_slug_idx=selected_slug_idx,
        user=user
    )

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
                        submodules.append({
                            "slug": slug,
                            "title": title,
                            "module": folder
                        })
                modules[folder] = submodules

    return render_template("user_modules.html", modules=modules, user=user)


@app.route('/mark_module/<slug>/<status>')
def mark_module(slug, status):
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    completed = (status.lower() == 'complete')

    existing = ModuleCompletion.query.filter_by(user_id=user_id, module_slug=slug).first()
    if completed and not existing:
        db.session.add(ModuleCompletion(user_id=user_id, module_slug=slug))
        db.session.commit()
    elif not completed and existing:
        db.session.delete(existing)
        db.session.commit()

    return redirect(url_for('module', slug=slug))


class CreateModuleForm(FlaskForm):
    module = StringField('Module (Folder)', validators=[DataRequired(), Regexp(r'^[A-Za-z0-9\- ]+$', message="Only letters, numbers, spaces, and dashes allowed.")])
    slug = StringField('Submodule Slug (Filename)', validators=[DataRequired(), Regexp(r'^[A-Za-z0-9\-]+$', message="Only letters, numbers, and dashes allowed.")])
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content (Markdown)', validators=[DataRequired()])
    submit = SubmitField('Create Module')

class EditModuleForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save Changes')

@app.route('/edit-module/<module>/<slug>', methods=['GET', 'POST'])
def edit_module(module, slug):
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user or user.role != 'admin':
        abort(403)

    path = f"modules_data/{module}/{slug}.md"
    backup_dir = "module_backups"
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)

    form = EditModuleForm()

    if form.validate_on_submit():
        new_content = form.content.data

        import time, shutil
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        if os.path.exists(path):
            backup_path = f"{backup_dir}/{module}-{slug}-{timestamp}.md"
            shutil.copy2(path, backup_path)

        uploaded_files = request.files.getlist("images")
        os.makedirs("static/uploads", exist_ok=True)

        for uploaded_file in uploaded_files:
            if uploaded_file and uploaded_file.filename != "":
                upload_path = os.path.join("static/uploads", uploaded_file.filename)
                uploaded_file.save(upload_path)
                new_content += f"\n\n![image](/static/uploads/{uploaded_file.filename})"

        with open(path, 'w') as f:
            f.write(new_content)

        return redirect(url_for('dashboard', msg=f"Submodule '{slug}' updated!"))

    if request.method == 'GET' and os.path.exists(path):
        with open(path, 'r') as f:
            form.content.data = f.read()
    else:
        return redirect(url_for('dashboard', error=f"Submodule '{slug}' not found."))

    return render_template('edit_module.html', slug=slug, form=form)


@app.route('/delete-module/<module>/<slug>', methods=['POST'])
def delete_module(module, slug):
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if not user or user.role != 'admin':
        abort(403)

    path = f"modules_data/{module}/{slug}.md"
    backup_dir = "module_backups"
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)

    import time, shutil
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    if os.path.exists(path):
        backup_path = f"{backup_dir}/{module}-{slug}-{timestamp}.md"
        shutil.copy2(path, backup_path)
        os.remove(path)
        return redirect(url_for('dashboard', msg=f"Submodule '{slug}' deleted successfully! (Backup created)"))
    else:
        return redirect(url_for('dashboard', error=f"Submodule '{slug}' not found."))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('adminpass123'),
                role='admin',
                paid=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("✅ Admin user created: admin / adminpass123")

    app.run(debug=True, host='0.0.0.0', port=3000)