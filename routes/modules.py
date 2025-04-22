"""Module routes for the BlackMoby application.

Contains routes for viewing and interacting with learning modules and submodules.
"""

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
    request,
)
from models import User, Module, Submodule, ModuleCompletion, UserLog
from extensions import db
from utils.decorators import login_required, subscription_required
import os
import markdown
import logging

# Create the blueprint
modules_bp = Blueprint("modules", __name__)

# Configure logging
logger = logging.getLogger("blackmoby")


@modules_bp.route("/modules")
@login_required
def modules_list():
    """Display all accessible modules"""
    user = User.query.get(session["user_id"])

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
                        user_id=user.id, submodule_id=submodule.id
                    ).first()

                    if completion:
                        completed_count += 1

                progress = int((completed_count / submodule_count) * 100)
            else:
                progress = 0

            # Add module with progress to accessible list
            accessible_modules.append(
                {
                    "module": module,
                    "progress": progress,
                    "completed": completed_count,
                    "total": submodule_count,
                }
            )

    return render_template("modules.html", user=user, modules=accessible_modules)


@modules_bp.route("/module/<module_slug>")
@login_required
def module_detail(module_slug):
    """Display a specific module with its submodules"""
    user = User.query.get(session["user_id"])
    module = Module.query.filter_by(slug=module_slug).first_or_404()

    # Check if user can access this module
    if not user.can_access_module(module_slug):
        flash("You need an active subscription to access this module", "error")
        return redirect(url_for("payment.pricing"))

    # Get all submodules for this module with completion status
    submodules_with_status = []
    for submodule in module.submodules:
        completion = ModuleCompletion.query.filter_by(
            user_id=user.id, submodule_id=submodule.id
        ).first()

        submodules_with_status.append(
            {
                "submodule": submodule,
                "completed": completion is not None,
                "completed_at": completion.completed_at if completion else None,
            }
        )

    return render_template(
        "module_detail.html",
        user=user,
        module=module,
        submodules=submodules_with_status,
    )


@modules_bp.route("/submodule/<module_slug>/<submodule_slug>")
@login_required
def submodule_detail(module_slug, submodule_slug):
    """Display a specific submodule content"""
    user = User.query.get(session["user_id"])
    module = Module.query.filter_by(slug=module_slug).first_or_404()

    # Check if user can access this module
    if not user.can_access_module(module_slug):
        flash("You need an active subscription to access this content", "error")
        return redirect(url_for("payment.pricing"))

    # Find the submodule
    submodule = Submodule.query.filter_by(
        module_id=module.id, slug=submodule_slug
    ).first_or_404()

    # Get content for the submodule (from file or database)
    try:
        content_file = f"content/modules/{module_slug}/{submodule_slug}.md"
        if os.path.exists(content_file):
            with open(content_file, "r") as f:
                content = f.read()
        else:
            content = "Content not found for this submodule."

        # Convert markdown to HTML
        html_content = markdown.markdown(content, extensions=["fenced_code", "tables"])
    except Exception as e:
        logger.error(f"Error loading submodule content: {str(e)}")
        html_content = "<p>Error loading content. Please try again later.</p>"

    # Check if user has completed this submodule
    completion = ModuleCompletion.query.filter_by(
        user_id=user.id, submodule_id=submodule.id
    ).first()

    # Get next and previous submodules for navigation
    submodules = module.submodules
    current_index = next(
        (i for i, s in enumerate(submodules) if s.id == submodule.id), -1
    )

    prev_submodule = submodules[current_index - 1] if current_index > 0 else None
    next_submodule = (
        submodules[current_index + 1] if current_index < len(submodules) - 1 else None
    )

    return render_template(
        "submodule_detail.html",
        user=user,
        module=module,
        submodule=submodule,
        content=html_content,
        completed=completion is not None,
        prev_submodule=prev_submodule,
        next_submodule=next_submodule,
    )


@modules_bp.route("/mark-complete/<int:submodule_id>", methods=["POST"])
@login_required
def mark_complete(submodule_id):
    """Mark a submodule as completed"""
    user = User.query.get(session["user_id"])
    submodule = Submodule.query.get_or_404(submodule_id)
    module = Module.query.get(submodule.module_id)

    # Check if user can access this module
    if not user.can_access_module(module.slug):
        return jsonify(success=False, error="Access denied"), 403

    # Check if already completed
    completion = ModuleCompletion.query.filter_by(
        user_id=user.id, submodule_id=submodule.id
    ).first()

    if not completion:
        # Mark as completed
        completion = ModuleCompletion(user_id=user.id, submodule_id=submodule.id)
        db.session.add(completion)
        db.session.add(
            UserLog(user_id=user.id, action=f"completed submodule {submodule.id}")
        )
        db.session.commit()

    return jsonify(success=True)
