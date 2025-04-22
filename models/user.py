from datetime import datetime, timedelta
from . import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default="user")
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(64), nullable=True)
    verification_sent_at = db.Column(db.DateTime, nullable=True)

    # Subscription information
    subscription_status = db.Column(
        db.String(20), default="inactive"
    )  # inactive, trial, active
    subscription_type = db.Column(
        db.String(20), nullable=True
    )  # trial, monthly, annual, lifetime
    subscription_start = db.Column(db.DateTime, nullable=True)
    subscription_end = db.Column(db.DateTime, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    last_login = db.Column(db.DateTime, nullable=True)

    # Relationships
    completions = db.relationship("ModuleCompletion", backref="user", lazy=True)
    logs = db.relationship("UserLog", backref="user", lazy=True)
    payments = db.relationship("Payment", backref="user", lazy=True)
    email_logs = db.relationship("EmailLog", backref="user", lazy=True)

    def has_active_subscription(self):
        """Check if user has an active subscription"""
        if self.role == "admin":
            return True

        if self.subscription_status not in ["active", "trial"]:
            return False

        # Lifetime subscriptions don't expire
        if self.subscription_type == "lifetime":
            return True

        # Check if subscription is still valid
        if self.subscription_end and self.subscription_end > datetime.utcnow():
            return True

        return False

    def can_access_module(self, module_slug):
        """Check if user can access a specific module"""
        from .module import Module

        # Admins can access everything
        if self.role == "admin":
            return True

        # Get the module
        module = Module.query.filter_by(slug=module_slug).first()
        if not module:
            return False

        # Modules marked as trial accessible can be accessed by anyone
        if module.trial_accessible:
            return True

        # Otherwise, require an active subscription
        return self.has_active_subscription()
