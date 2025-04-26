from flask import Blueprint, render_template, redirect, url_for, request, flash, abort, session
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, SelectField, SubmitField
from wtforms.validators import DataRequired, Regexp
import os
import markdown
import time
import shutil
import json
from datetime import datetime, timedelta
from models import db, User, ModuleCompletion, UserLog, Module, Submodule, Subscription, PaymentPlan
from werkzeug.utils import secure_filename
from functools import wraps

# Create admin blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Admin authorization decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        user = User.query.get(user_id)
        if not user or user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Forms
class CreateModuleForm(FlaskForm):
    module = StringField('Module (Folder)', validators=[DataRequired(), Regexp(r'^[A-Za-z0-9\- ]+$', message="Only letters, numbers, spaces, and dashes allowed.")])
    slug = StringField('Submodule Slug (Filename)', validators=[DataRequired(), Regexp(r'^[A-Za-z0-9\-]+$', message="Only letters, numbers, and dashes allowed.")])
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content (Markdown)', validators=[DataRequired()])
    submit = SubmitField('Create Module')

class EditModuleForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save Changes')

class UploadLabForm(FlaskForm):
    module = SelectField('Module', validators=[DataRequired()])
    title = StringField('Lab Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    lab_file = FileField('Lab File (ZIP)')
    submit = SubmitField('Upload Lab')

class ManageUserForm(FlaskForm):
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')])
    plan_type = SelectField('Subscription Plan', choices=[
        ('trial', 'Trial'), 
        ('yearly', 'Yearly'), 
        ('lifetime', 'Lifetime')
    ])
    submit = SubmitField('Update User')

# Routes
@admin_bp.route('/')
@admin_required
def dashboard():
    """Admin dashboard showing modules and submodules"""
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

    msg = request.args.get("msg")
    error = request.args.get("error")
    return render_template("admin/dashboard.html", modules=modules, msg=msg, error=error)

@admin_bp.route('/create-module', methods=['GET', 'POST'])
@admin_required
def create_module():
    """Create a new module or submodule"""
    form = CreateModuleForm()

    # Get list of existing modules
    existing_modules = []
    base_path = "modules_data"
    if os.path.exists(base_path):
        for folder in os.listdir(base_path):
            folder_path = os.path.join(base_path, folder)
            if os.path.isdir(folder_path):
                existing_modules.append(folder)

    if request.method == 'POST':
        module_option = request.form.get('module_option', 'new')

        # Handle module selection based on radio button choice
        if module_option == 'new':
            new_module_name = request.form.get('new_module', '').strip()
            if not new_module_name:
                return render_template('admin/create_module.html', 
                                     form=form, 
                                     existing_modules=existing_modules,
                                     error="New module name is required when creating a new module.")

            module = new_module_name.lower().replace(' ', '-')
            msg_prefix = f"Module folder '{module}' created! "
        else:  # existing module selected
            module = request.form.get('existing_module', '').strip()
            if not module:
                return render_template('admin/create_module.html', 
                                     form=form, 
                                     existing_modules=existing_modules,
                                     error="Please select an existing module.")
            msg_prefix = ""

        slug = request.form.get('slug', '').strip().lower()
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '')

        # Validate required fields
        if not slug or not title or not content:
            return render_template('admin/create_module.html', 
                                 form=form, 
                                 existing_modules=existing_modules,
                                 error="All fields are required.")

        folder_path = f"modules_data/{module}"
        os.makedirs(folder_path, exist_ok=True)

        filepath = f"{folder_path}/{slug}.md"
        if os.path.exists(filepath):
            return render_template('admin/create_module.html', 
                                 form=form, 
                                 existing_modules=existing_modules,
                                 error=f"Submodule '{slug}' already exists in module '{module}'.")

        uploaded_files = request.files.getlist("images")
        os.makedirs("static/uploads", exist_ok=True)

        for uploaded_file in uploaded_files:
            if uploaded_file and uploaded_file.filename != "":
                filename = secure_filename(uploaded_file.filename)
                upload_path = os.path.join("static/uploads", filename)
                uploaded_file.save(upload_path)
                content += f"\n\n![image](/static/uploads/{filename})"

        with open(filepath, 'w') as f:
            f.write(f"# {title}\n\n" + content)

        # Add to database if using the database model
        try:
            # Check if module exists in database
            module_obj = Module.query.filter_by(slug=module).first()
            if not module_obj:
                module_obj = Module(
                    title=module.replace('-', ' ').title(),
                    slug=module,
                    description=f"Module for {module.replace('-', ' ').title()}",
                    trial_accessible=True
                )
                db.session.add(module_obj)
                db.session.commit()

            # Add submodule to database
            submodule = Submodule(
                module_id=module_obj.id,
                title=title,
                content=content,
                order=len(module_obj.submodules) + 1
            )
            db.session.add(submodule)
            db.session.commit()
        except Exception as e:
            # Continue even if database operation fails
            # Just log the error
            print(f"Database error: {str(e)}")

        return redirect(url_for('admin.dashboard', msg=f"{msg_prefix}Submodule '{slug}' created under '{module}'!"))

    return render_template('admin/create_module.html', 
                         form=form, 
                         existing_modules=existing_modules)

@admin_bp.route('/edit-module/<module>/<slug>', methods=['GET', 'POST'])
@admin_required
def edit_module(module, slug):
    """Edit an existing module"""
    path = f"modules_data/{module}/{slug}.md"
    backup_dir = "module_backups"
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)

    form = EditModuleForm()

    if form.validate_on_submit():
        new_content = form.content.data

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        if os.path.exists(path):
            backup_path = f"{backup_dir}/{module}-{slug}-{timestamp}.md"
            shutil.copy2(path, backup_path)

        uploaded_files = request.files.getlist("images")
        os.makedirs("static/uploads", exist_ok=True)

        for uploaded_file in uploaded_files:
            if uploaded_file and uploaded_file.filename != "":
                filename = secure_filename(uploaded_file.filename)
                upload_path = os.path.join("static/uploads", filename)
                uploaded_file.save(upload_path)
                new_content += f"\n\n![image](/static/uploads/{filename})"

        with open(path, 'w') as f:
            f.write(new_content)

        # Update in database if using the database model
        try:
            module_obj = Module.query.filter_by(slug=module).first()
            if module_obj:
                submodule = Submodule.query.filter(
                    Submodule.module_id == module_obj.id,
                    Submodule.title.like(f"%{slug.replace('-', ' ')}%")
                ).first()

                if submodule:
                    submodule.content = new_content
                    db.session.commit()
        except Exception as e:
            # Continue even if database operation fails
            print(f"Database error: {str(e)}")

        return redirect(url_for('admin.dashboard', msg=f"Submodule '{slug}' updated!"))

    if request.method == 'GET' and os.path.exists(path):
        with open(path, 'r') as f:
            form.content.data = f.read()
    else:
        return redirect(url_for('admin.dashboard', error=f"Submodule '{slug}' not found."))

    return render_template('admin/edit_module.html', slug=slug, form=form)

@admin_bp.route('/delete-module/<module>/<slug>', methods=['POST'])
@admin_required
def delete_module(module, slug):
    """Delete a module"""
    path = f"modules_data/{module}/{slug}.md"
    backup_dir = "module_backups"
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    if os.path.exists(path):
        backup_path = f"{backup_dir}/{module}-{slug}-{timestamp}.md"
        shutil.copy2(path, backup_path)
        os.remove(path)

        # Remove from database if using the database model
        try:
            module_obj = Module.query.filter_by(slug=module).first()
            if module_obj:
                submodule = Submodule.query.filter(
                    Submodule.module_id == module_obj.id,
                    Submodule.title.like(f"%{slug.replace('-', ' ')}%")
                ).first()

                if submodule:
                    db.session.delete(submodule)
                    db.session.commit()
        except Exception as e:
            # Continue even if database operation fails
            print(f"Database error: {str(e)}")

        return redirect(url_for('admin.dashboard', msg=f"Submodule '{slug}' deleted successfully! (Backup created)"))
    else:
        return redirect(url_for('admin.dashboard', error=f"Submodule '{slug}' not found."))

@admin_bp.route('/labs', methods=['GET'])
@admin_required
def manage_labs():
    """Manage lab materials"""
    labs = []
    try:
        modules = Module.query.all()
        for module in modules:
            if module.has_lab:
                labs.append({
                    'id': module.id,
                    'title': module.title,
                    'slug': module.slug,
                    'lab_file': module.lab_file
                })
    except Exception:
        # If database is not set up, try reading from file
        labs_dir = "lab_materials"
        if os.path.exists(labs_dir):
            for filename in os.listdir(labs_dir):
                if filename.endswith(".zip"):
                    labs.append({
                        'title': filename.replace('.zip', '').replace('-', ' ').title(),
                        'slug': filename.replace('.zip', ''),
                        'lab_file': filename
                    })

    return render_template('admin/labs.html', labs=labs)

@admin_bp.route('/upload-lab', methods=['GET', 'POST'])
@admin_required
def upload_lab():
    """Upload lab materials"""
    form = UploadLabForm()

    # Populate module choices
    modules = []
    try:
        modules = [(m.slug, m.title) for m in Module.query.all()]
    except Exception:
        # If database is not set up, try reading from file system
        base_path = "modules_data"
        if os.path.exists(base_path):
            for folder in os.listdir(base_path):
                if os.path.isdir(os.path.join(base_path, folder)):
                    modules.append((folder, folder.replace('-', ' ').title()))

    form.module.choices = modules

    if form.validate_on_submit():
        module_slug = form.module.data
        title = form.title.data
        description = form.description.data
        lab_file = form.lab_file.data

        if lab_file and lab_file.filename != "":
            # Create labs directory if it doesn't exist
            lab_dir = "lab_materials"
            os.makedirs(lab_dir, exist_ok=True)

            # Save the lab file
            filename = secure_filename(lab_file.filename)
            lab_path = os.path.join(lab_dir, filename)
            lab_file.save(lab_path)

            # Save lab info to database
            try:
                module = Module.query.filter_by(slug=module_slug).first()
                if module:
                    module.has_lab = True
                    module.lab_file = filename
                    db.session.commit()
            except Exception as e:
                # Continue even if database operation fails
                print(f"Database error: {str(e)}")

                # Save lab info to JSON file as fallback
                lab_info_file = os.path.join(lab_dir, "lab_info.json")
                lab_info = {}

                if os.path.exists(lab_info_file):
                    with open(lab_info_file, 'r') as f:
                        try:
                            lab_info = json.load(f)
                        except json.JSONDecodeError:
                            lab_info = {}

                lab_info[module_slug] = {
                    'title': title,
                    'description': description,
                    'file': filename,
                    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }

                with open(lab_info_file, 'w') as f:
                    json.dump(lab_info, f, indent=2)

            flash(f"Lab materials for '{title}' uploaded successfully!", "success")
            return redirect(url_for('admin.manage_labs'))
        else:
            flash("Please upload a lab file.", "error")

    return render_template('admin/upload_lab.html', form=form)

@admin_bp.route('/delete-lab/<slug>', methods=['POST'])
@admin_required
def delete_lab(slug):
    """Delete lab materials"""
    try:
        module = Module.query.filter_by(slug=slug).first()
        if module and module.has_lab:
            # Remove the lab file
            lab_file = module.lab_file
            lab_path = os.path.join("lab_materials", lab_file)
            if os.path.exists(lab_path):
                os.remove(lab_path)

            # Update the database
            module.has_lab = False
            module.lab_file = None
            db.session.commit()

            flash(f"Lab materials for '{module.title}' deleted successfully!", "success")
        else:
            flash(f"Lab materials for '{slug}' not found.", "error")
    except Exception:
        # Fallback to file-based approach
        lab_dir = "lab_materials"
        lab_file = os.path.join(lab_dir, f"{slug}.zip")
        if os.path.exists(lab_file):
            os.remove(lab_file)

            # Update the JSON file
            lab_info_file = os.path.join(lab_dir, "lab_info.json")
            if os.path.exists(lab_info_file):
                with open(lab_info_file, 'r') as f:
                    try:
                        lab_info = json.load(f)
                        if slug in lab_info:
                            del lab_info[slug]
                            with open(lab_info_file, 'w') as f:
                                json.dump(lab_info, f, indent=2)
                    except json.JSONDecodeError:
                        pass

            flash(f"Lab materials for '{slug}' deleted successfully!", "success")
        else:
            flash(f"Lab materials for '{slug}' not found.", "error")

    return redirect(url_for('admin.manage_labs'))

@admin_bp.route('/users')
@admin_required
def manage_users():
    """Manage users"""
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/edit-user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    """Edit a user"""
    user = User.query.get_or_404(user_id)
    form = ManageUserForm()

    if form.validate_on_submit():
        user.role = form.role.data

        # Update subscription
        new_plan_type = form.plan_type.data
        if user.subscription:
            user.subscription.plan_type = new_plan_type
            if new_plan_type == 'trial':
                user.subscription.end_date = datetime.utcnow() + timedelta(days=14)
            elif new_plan_type == 'yearly':
                user.subscription.end_date = datetime.utcnow() + timedelta(days=365)
            elif new_plan_type == 'lifetime':
                user.subscription.end_date = None
        else:
            end_date = None
            if new_plan_type == 'trial':
                end_date = datetime.utcnow() + timedelta(days=14)
            elif new_plan_type == 'yearly':
                end_date = datetime.utcnow() + timedelta(days=365)

            subscription = Subscription(
                user_id=user.id,
                plan_type=new_plan_type,
                start_date=datetime.utcnow(),
                end_date=end_date,
                active=True
            )
            db.session.add(subscription)

        db.session.commit()
        flash(f"User {user.username} updated successfully!", "success")
        return redirect(url_for('admin.manage_users'))

    if request.method == 'GET':
        form.role.data = user.role
        if user.subscription:
            form.plan_type.data = user.subscription.plan_type
        else:
            form.plan_type.data = 'trial'

    return render_template('admin/edit_user.html', form=form, user=user)

@admin_bp.route('/stats')
@admin_required
def stats():
    """View statistics"""
    stats_data = {
        'total_users': 0,
        'total_modules': 0,
        'total_submodules': 0,
        'popular_modules': [],
        'recent_completions': [],
        'subscription_distribution': {'trial': 0, 'yearly': 0, 'lifetime': 0}
    }

    try:
        # Basic counts
        stats_data['total_users'] = User.query.count()
        stats_data['total_modules'] = Module.query.count()
        stats_data['total_submodules'] = Submodule.query.count()

        # Subscription distribution
        for sub_type in ['trial', 'yearly', 'lifetime']:
            stats_data['subscription_distribution'][sub_type] = Subscription.query.filter_by(plan_type=sub_type).count()

        # Popular modules (based on completions)
        popular_modules_query = db.session.query(
            Submodule.module_id, 
            Module.title,
            db.func.count(ModuleCompletion.id).label('completion_count')
        ).join(ModuleCompletion, ModuleCompletion.submodule_id == Submodule.id)\
         .join(Module, Module.id == Submodule.module_id)\
         .group_by(Submodule.module_id)\
         .order_by(db.desc('completion_count'))\
         .limit(5)

        stats_data['popular_modules'] = [
            {'title': row.title, 'count': row.completion_count}
            for row in popular_modules_query
        ]

        # Recent completions
        recent_completions_query = db.session.query(
            User.username,
            Submodule.title,
            ModuleCompletion.completed_at
        ).join(User, User.id == ModuleCompletion.user_id)\
         .join(Submodule, Submodule.id == ModuleCompletion.submodule_id)\
         .order_by(db.desc(ModuleCompletion.completed_at))\
         .limit(10)

        stats_data['recent_completions'] = [
            {
                'username': row.username,
                'module': row.title,
                'completed_at': row.completed_at.strftime('%Y-%m-%d %H:%M')
            }
            for row in recent_completions_query
        ]
    except Exception as e:
        # If database queries fail, use placeholder data
        print(f"Database error: {str(e)}")

        # Count modules and submodules from file system
        base_path = "modules_data"
        module_count = 0
        submodule_count = 0

        if os.path.exists(base_path):
            module_folders = [f for f in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, f))]
            module_count = len(module_folders)

            for folder in module_folders:
                folder_path = os.path.join(base_path, folder)
                submodules = [f for f in os.listdir(folder_path) if f.endswith('.md')]
                submodule_count += len(submodules)

        stats_data['total_modules'] = module_count
        stats_data['total_submodules'] = submodule_count

    return render_template('admin/stats.html', stats=stats_data).query.filter_by(slug=module).first()
            if not module_obj:
                module_obj = Module