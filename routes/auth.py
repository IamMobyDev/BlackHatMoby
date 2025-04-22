"""Authentication routes for the BlackMoby application.

Contains routes for login, registration, logout, and email verification.
"""

from flask import Blueprint, render_template, redirect, url_for, session, request, flash
from models import db, User, UserLog
from forms.auth import LoginForm, RegistrationForm
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from utils.email import send_email
from extensions import limiter
import uuid
import logging

# Create the blueprint
auth_bp = Blueprint("auth", __name__)

# Configure logging
logger = logging.getLogger("blackmoby")


def generate_verification_token():
    """Generate a unique verification token"""
    return str(uuid.uuid4())


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    """User login page"""
    if "user_id" in session:
        return redirect(url_for("modules.modules_list"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password_hash, form.password.data):
            session.permanent = True
            session["user_id"] = user.id
            session["role"] = user.role

            # Update last login time
            user.last_login = datetime.utcnow()
            db.session.add(UserLog(user_id=user.id, action="logged in"))
            db.session.commit()

            # Redirect to the next page or modules/pricing based on subscription
            next_page = request.args.get("next")
            if next_page:
                return redirect(next_page)
            elif user.has_active_subscription():
                return redirect(url_for("modules.modules_list"))
            else:
                return redirect(url_for("payment.pricing"))

        flash("Invalid username or password", "error")

    return render_template("login.html", form=form)


@auth_bp.route("/logout")
def logout():
    """User logout"""
    user_id = session.get("user_id")
    if user_id:
        db.session.add(UserLog(user_id=user_id, action="logged out"))
        db.session.commit()

    session.clear()
    return redirect(url_for("main.index"))


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    """User registration page"""
    if "user_id" in session:
        return redirect(url_for("modules.modules_list"))

    form = RegistrationForm()
    if form.validate_on_submit():
        # Create new user
        verification_token = generate_verification_token()
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=generate_password_hash(form.password.data),
            verification_token=verification_token,
            verification_sent_at=datetime.utcnow(),
        )

        db.session.add(new_user)
        db.session.commit()  # Need to commit to get new_user.id

        db.session.add(UserLog(user_id=new_user.id, action="registered"))
        db.session.commit()

        # Send verification email
        send_email(
            subject="Verify Your Email Address",
            recipient=new_user.email,
            template="emails/verify_email.html",
            user_id=new_user.id,
            email_type="verification",
            username=new_user.username,
            verification_url=url_for(
                "auth.verify_email", token=verification_token, _external=True
            ),
        )

        # Log the user in
        session.permanent = True
        session["user_id"] = new_user.id
        session["role"] = new_user.role

        flash(
            "Account created successfully! Please check your email to verify your account.",
            "success",
        )
        return redirect(url_for("payment.pricing"))

    return render_template("register.html", form=form)


@auth_bp.route("/verify-email/<token>")
def verify_email(token):
    """Email verification route"""
    user = User.query.filter_by(verification_token=token).first()

    if not user:
        flash("Invalid or expired verification link", "error")
        return redirect(url_for("main.index"))

    # Verify user's email
    user.is_verified = True
    user.verification_token = None
    db.session.add(UserLog(user_id=user.id, action="verified email"))
    db.session.commit()

    flash(
        "Your email has been verified! You can now fully use your account.", "success"
    )

    # Log the user in if not already logged in
    if "user_id" not in session:
        session.permanent = True
        session["user_id"] = user.id
        session["role"] = user.role

    return redirect(url_for("payment.pricing"))
