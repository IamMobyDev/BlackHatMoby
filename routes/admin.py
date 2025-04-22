from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    abort,
    session,
)
from datetime import datetime, timedelta

from models import User, Module, Submodule, ModuleCompletion, Payment, PaymentPlan, UserLog
from forms.module import CreateModuleForm, CreateSubmoduleForm
from utils.decorators import admin_required
from extensions import db

import os
import logging

logger = logging.getLogger("blackmoby")

# Initialize blueprint
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@admin_required
def dashboard():
    """Admin dashboard"""
    # Get basic statistics
    total_users = User.query.count()
    active_users = User.query.filter(User.subscription_status == "active").count()
    trial_users = User.query.filter(User.subscription_status == "trial").count()

    # Get recent registrations
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()

    # Get recent payments
    recent_payments = (
        Payment.query.filter_by(status="completed")
        .order_by(Payment.updated_at.desc())
        .limit(10)
        .all()
    )

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        active_users=active_users,
        trial_users=trial_users,
        recent_users=recent_users,
        recent_payments=recent_payments,
    )


@admin_bp.route("/modules")
@admin_required
def modules():
    """Admin module management"""
    modules = Module.query.order_by(Module.order).all()
    form = CreateModuleForm()

    return render_template("admin/modules.html", modules=modules, form=form)


@admin_bp.route("/modules/create", methods=["POST"])
@admin_required
def create_module():
    """Create a new module"""
    form = CreateModuleForm()

    if form.validate_on_submit():
        # Check if module with this slug already exists
        existing = Module.query.filter_by(slug=form.slug.data).first()
        if existing:
            flash("A module with this slug already exists", "error")
            return redirect(url_for("admin.modules"))

        # Create new module
        module = Module(
            title=form.title.data,
            slug=form.slug.data,
            description=form.description.data,
            order=form.order.data,
            trial_accessible=form.trial_accessible.data,
        )

        db.session.add(module)
        db.session.commit()

        # Create directory for module content if it doesn't exist
        module_dir = f"content/modules/{module.slug}"
        os.makedirs(module_dir, exist_ok=True)

        flash(f'Module "{module.title}" created successfully', "success")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", "error")

    return redirect(url_for("admin.modules"))


@admin_bp.route("/modules/<int:module_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_module(module_id):
    """Edit a module"""
    module = Module.query.get_or_404(module_id)

    if request.method == "POST":
        # Update module fields
        module.title = request.form.get("title")
        module.description = request.form.get("description")
        module.order = int(request.form.get("order", 0))
        module.trial_accessible = request.form.get("trial_accessible") == "on"

        db.session.commit()
        flash(f'Module "{module.title}" updated successfully', "success")
        return redirect(url_for("admin.modules"))

    return render_template("admin/edit_module.html", module=module)


@admin_bp.route("/submodules")
@admin_required
def submodules():
    """Admin submodule management"""
    submodules = (
        Submodule.query.join(Module).order_by(Module.order, Submodule.order).all()
    )

    # Create form for new submodule
    form = CreateSubmoduleForm()
    form.module_id.choices = [
        (m.id, m.title) for m in Module.query.order_by(Module.order).all()
    ]

    return render_template("admin/submodules.html", submodules=submodules, form=form)


@admin_bp.route("/submodules/create", methods=["POST"])
@admin_required
def create_submodule():
    """Create a new submodule"""
    form = CreateSubmoduleForm()
    form.module_id.choices = [
        (m.id, m.title) for m in Module.query.order_by(Module.order).all()
    ]

    if form.validate_on_submit():
        module = Module.query.get(form.module_id.data)
        if not module:
            flash("Selected module does not exist", "error")
            return redirect(url_for("admin.submodules"))

        # Check if submodule with this slug already exists for this module
        existing = Submodule.query.filter_by(
            module_id=module.id, slug=form.slug.data
        ).first()
        if existing:
            flash("A submodule with this slug already exists for this module", "error")
            return redirect(url_for("admin.submodules"))

        # Create new submodule
        submodule = Submodule(
            module_id=module.id,
            title=form.title.data,
            slug=form.slug.data,
            order=form.order.data,
        )

        db.session.add(submodule)
        db.session.commit()

        # Save content to file
        submodule_file = f"content/modules/{module.slug}/{form.slug.data}.md"
        os.makedirs(os.path.dirname(submodule_file), exist_ok=True)

        with open(submodule_file, "w") as f:
            f.write(form.content.data)

        flash(f'Submodule "{submodule.title}" created successfully', "success")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", "error")

    return redirect(url_for("admin.submodules"))


@admin_bp.route("/submodules/<int:submodule_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_submodule(submodule_id):
    """Edit a submodule"""
    submodule = Submodule.query.get_or_404(submodule_id)
    module = Module.query.get(submodule.module_id)

    # Load content from file
    content_file = f"content/modules/{module.slug}/{submodule.slug}.md"
    try:
        if os.path.exists(content_file):
            with open(content_file, "r") as f:
                content = f.read()
        else:
            content = ""
    except Exception as e:
        logger.error(f"Error loading submodule content: {str(e)}")
        content = ""

    if request.method == "POST":
        # Update submodule fields
        submodule.title = request.form.get("title")
        submodule.order = int(request.form.get("order", 0))

        # Save content to file
        with open(content_file, "w") as f:
            f.write(request.form.get("content", ""))

        db.session.commit()
        flash(f'Submodule "{submodule.title}" updated successfully', "success")
        return redirect(url_for("admin.submodules"))

    return render_template(
        "admin/edit_submodule.html", submodule=submodule, module=module, content=content
    )


@admin_bp.route("/users")
@admin_required
def users():
    """Admin user management"""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users)


@admin_bp.route("/users/<int:user_id>")
@admin_required
def user_detail(user_id):
    """Admin user detail view"""
    user = User.query.get_or_404(user_id)

    # Get user logs
    logs = (
        UserLog.query.filter_by(user_id=user.id)
        .order_by(UserLog.timestamp.desc())
        .all()
    )

    # Get user payments
    payments = (
        Payment.query.filter_by(user_id=user.id)
        .order_by(Payment.created_at.desc())
        .all()
    )

    # Get module progress
    module_progress = []
    for module in Module.query.order_by(Module.order).all():
        if user.can_access_module(module.slug):
            submodule_count = len(module.submodules)
            completed_count = 0

            for submodule in module.submodules:
                completion = ModuleCompletion.query.filter_by(
                    user_id=user.id, submodule_id=submodule.id
                ).first()

                if completion:
                    completed_count += 1

            if submodule_count > 0:
                progress = int((completed_count / submodule_count) * 100)
            else:
                progress = 0

            module_progress.append(
                {
                    "module": module,
                    "progress": progress,
                    "completed": completed_count,
                    "total": submodule_count,
                }
            )

    return render_template(
        "admin/user_detail.html",
        user=user,
        logs=logs,
        payments=payments,
        module_progress=module_progress,
    )


@admin_bp.route("/users/<int:user_id>/update", methods=["POST"])
@admin_required
def update_user(user_id):
    """Update user from admin panel"""
    user = User.query.get_or_404(user_id)

    # Update user fields
    if "role" in request.form:
        user.role = request.form.get("role")

    if "subscription_status" in request.form:
        user.subscription_status = request.form.get("subscription_status")

    if "subscription_type" in request.form:
        user.subscription_type = request.form.get("subscription_type")

    if "subscription_end" in request.form:
        end_date = request.form.get("subscription_end")
        if end_date:
            user.subscription_end = datetime.fromisoformat(end_date)
        else:
            user.subscription_end = None

    db.session.add(UserLog(user_id=user.id, action=f"admin updated user profile"))
    db.session.commit()

    flash(f'User "{user.username}" updated successfully', "success")
    return redirect(url_for("admin.user_detail", user_id=user.id))


@admin_bp.route("/payments")
@admin_required
def payments():
    """Admin payment management"""
    payments = Payment.query.order_by(Payment.created_at.desc()).all()
    return render_template("admin/payments.html", payments=payments)


@admin_bp.route("/plans")
@admin_required
def plans():
    """Admin payment plan management"""
    plans = PaymentPlan.query.order_by(PaymentPlan.price_usd).all()
    return render_template("admin/plans.html", plans=plans)


@admin_bp.route("/plans/create", methods=["GET", "POST"])
@admin_required
def create_plan():
    """Create a new payment plan"""
    if request.method == "POST":
        # Create new plan
        plan = PaymentPlan(
            name=request.form.get("name"),
            slug=request.form.get("slug"),
            description=request.form.get("description"),
            price_usd=int(
                float(request.form.get("price_usd", 0)) * 100
            ),  # Convert to cents
            duration_days=(
                int(request.form.get("duration_days", 0))
                if request.form.get("duration_days")
                else None
            ),
            is_active=request.form.get("is_active") == "on",
        )

        db.session.add(plan)
        db.session.commit()

        flash(f'Plan "{plan.name}" created successfully', "success")
        return redirect(url_for("admin.plans"))

    return render_template("admin/create_plan.html")


@admin_bp.route("/plans/<int:plan_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_plan(plan_id):
    """Edit a payment plan"""
    plan = PaymentPlan.query.get_or_404(plan_id)

    if request.method == "POST":
        # Update plan
        plan.name = request.form.get("name")
        plan.description = request.form.get("description")
        plan.price_usd = int(
            float(request.form.get("price_usd", 0)) * 100
        )  # Convert to cents

        duration_days = request.form.get("duration_days")
        plan.duration_days = int(duration_days) if duration_days else None

        plan.is_active = request.form.get("is_active") == "on"

        db.session.commit()

        flash(f'Plan "{plan.name}" updated successfully', "success")
        return redirect(url_for("admin.plans"))

    return render_template("admin/edit_plan.html", plan=plan)