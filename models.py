from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    paid = db.Column(db.Boolean, default=False)
    subscription_type = db.Column(db.String(20), default=None, nullable=True)  # 'annual' or 'lifetime'
    subscription_end = db.Column(db.DateTime, nullable=True)
    # Additional fields needed for email verification
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    verification_sent_at = db.Column(db.DateTime, nullable=True)
    # Fields for subscription tracking
    subscription_status = db.Column(db.String(20), default=None, nullable=True)  # 'active', 'expired', 'trial'
    subscription_start = db.Column(db.DateTime, nullable=True)
    
    def has_active_subscription(self):
        """Check if user has an active subscription"""
        # Admin always has access
        if self.role == 'admin':
            return True
            
        # Check for lifetime subscription
        if self.subscription_status == 'active' and self.subscription_type == 'lifetime':
            return True
            
        # Check for active time-limited subscription
        if self.subscription_status in ['active', 'trial'] and self.subscription_end:
            return datetime.utcnow() <= self.subscription_end
            
        return False
        
    def can_access_module(self, module_slug):
        """Check if user can access a specific module"""
        # Admin can access everything
        if self.role == 'admin':
            return True
            
        # Get the module
        module = Module.query.filter_by(slug=module_slug).first()
        if not module:
            return False
            
        # Trial modules are accessible to everyone
        if module.trial_accessible:
            return True
            
        # Otherwise, check for active subscription
        return self.has_active_subscription()

class Module(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    order = db.Column(db.Integer, default=0)  # For display order
    trial_accessible = db.Column(db.Boolean, default=False)  # Whether accessible in trial mode
    
    # Relationship with submodules
    submodules = db.relationship('Submodule', back_populates='module', order_by='Submodule.order')

class Submodule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    module_id = db.Column(db.Integer, db.ForeignKey('module.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), nullable=False)
    order = db.Column(db.Integer, default=0)  # For display order
    
    # Relationship with module
    module = db.relationship('Module', back_populates='submodules')
    
    # Ensure unique slug within a module
    __table_args__ = (db.UniqueConstraint('module_id', 'slug', name='_module_slug_uc'),)

class ModuleCompletion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submodule_id = db.Column(db.Integer, db.ForeignKey('submodule.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('completed_modules', lazy=True))
    submodule = db.relationship('Submodule', backref=db.backref('completions', lazy=True))

class UserLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('logs', lazy=True))

class PaymentPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    price_usd = db.Column(db.Integer, nullable=False)  # Amount in cents
    duration_days = db.Column(db.Integer, nullable=True)  # None for lifetime plans
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('payment_plan.id'), nullable=False)
    reference = db.Column(db.String(100), nullable=False, unique=True)
    amount = db.Column(db.Integer, nullable=False)  # Amount in cents
    transaction_id = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'completed', 'failed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    retries = db.Column(db.Integer, default=0)
    verification_logs = db.Column(db.Text, nullable=True)
    
    user = db.relationship('User', backref=db.backref('payments', lazy=True))
    plan = db.relationship('PaymentPlan', backref=db.backref('payments', lazy=True))

class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email_type = db.Column(db.String(50), nullable=False)  # verification, welcome, payment_confirmation, etc.
    subject = db.Column(db.String(255), nullable=False)
    recipient = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # sent, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('email_logs', lazy=True))

# Keep your existing PaymentAttempt model for backward compatibility
class PaymentAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reference = db.Column(db.String(100), nullable=False, unique=True)
    amount = db.Column(db.Integer, nullable=False)  # Amount in kobo/cents
    plan_type = db.Column(db.String(20), nullable=False)  # 'annual' or 'lifetime'
    transaction_id = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'completed', 'failed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)  # Store IP for fraud detection

    # Added for security audit
    retries = db.Column(db.Integer, default=0)  # Track verification retries
    verification_logs = db.Column(db.Text, nullable=True)  # Store logs during verification process

    user = db.relationship('User', backref=db.backref('payment_attempts', lazy=True))