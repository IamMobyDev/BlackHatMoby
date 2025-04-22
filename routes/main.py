"""Main routes for the BlackMoby application.

Contains the primary public-facing routes that don't fit in other categories.
"""

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    session,
    request,
    jsonify,
)
from models import User
from utils.decorators import login_required
import logging
from flask_wtf.csrf import generate_csrf
from datetime import datetime

# Create the blueprint
main_bp = Blueprint("main", __name__)

# Configure logging
logger = logging.getLogger("blackmoby")


@main_bp.route("/")
def index():
    """Landing page"""
    if "user_id" in session:
        user = User.query.get(session["user_id"])
        if user and user.subscription_type:
            return redirect(url_for("modules.modules_list"))
    return render_template("landing.html")


@main_bp.route("/profile")
@login_required
def profile():
    """User profile page"""
    user = User.query.get(session["user_id"])

    # Get user statistics
    total_modules = User.query.count()
    accessible_modules = 0
    completed_submodules = 0
    total_accessible_submodules = 0

    # Calculate modules and submodules statistics
    for module in User.query.all():
        if user.can_access_module(module.slug):
            accessible_modules += 1
            for submodule in module.submodules:
                total_accessible_submodules += 1

                completion = User.query.filter_by(
                    user_id=user.id, submodule_id=submodule.id
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
        if user.subscription_type == "lifetime":
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
    recent_logs = (
        User.query.filter_by(user_id=user.id)
        .order_by(User.timestamp.desc())
        .limit(10)
        .all()
    )

    return render_template(
        "profile.html",
        user=user,
        progress=progress,
        completed=completed_submodules,
        total=total_accessible_submodules,
        accessible_modules=accessible_modules,
        total_modules=total_modules,
        subscription_info=subscription_info,
        recent_logs=recent_logs,
    )


# CSRF token route for AJAX requests
@main_bp.route("/get-csrf-token")
def get_csrf_token():
    if "user_id" not in session:
        return jsonify(error="Not authenticated"), 401

    return jsonify(csrf_token=generate_csrf())


# Error handlers
@main_bp.app_errorhandler(404)
def page_not_found(e):
    return render_template("errors/404.html"), 404


@main_bp.app_errorhandler(403)
def forbidden(e):
    return render_template("errors/403.html"), 403


@main_bp.app_errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}")
    return render_template("errors/500.html"), 500