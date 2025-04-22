from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize SQLAlchemy instance
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)  # 'user' or 'admin'
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    verification_sent_at = db.Column(db.DateTime, nullable=True)

    # Subscription fields
    subscription_status = db.Column(db.String(20), default='none', nullable=False)  # 'none', 'active', 'trial', 'expired'
    subscription_type = db.Column(db.String(20), nullable=True)  # 'trial', 'monthly', 'annual', 'lifetime'
    subscription_start = db.Column(db.DateTime, nullable=True)
    subscription_end = db.Column(db.DateTime, nullable=True)

    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    module_completions = db.relationship('ModuleCompletion', backref='user', lazy=True)
    logs = db.relationship('UserLog', backref='user', lazy=True)
    payments = db.relationship('Payment', backref='user', lazy=True)
    email_logs = db.relationship('EmailLog', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_active_subscription(self):
        if self.role == 'admin':
            return True

        if self.subscription_status not in ['active', 'trial']:
            return False

        # Check if subscription has expired
        if self.subscription_end and datetime.utcnow() > self.subscription_end:
            self.subscription_status = 'expired'
            db.session.commit()
            return False

        return True

    def can_access_module(self, module_slug):
        # Admins can access everything
        if self.role == 'admin':
            return True

        # Check if module is trial accessible
        module = Module.query.filter_by(slug=module_slug).first()
        if not module:
            return False

        if module.trial_accessible:
            return True

        # Check if user has an active subscription
        return self.has_active_subscription()


class Module(db.Model):
    __tablename__ = 'modules'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    order = db.Column(db.Integer, default=0)
    trial_accessible = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    submodules = db.relationship('Submodule', backref='module', lazy=True, order_by='Submodule.order')


class Submodule(db.Model):
    __tablename__ = 'submodules'

    id = db.Column(db.Integer, primary_key=True)
    module_id = db.Column(db.Integer, db.ForeignKey('modules.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), nullable=False)
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    completions = db.relationship('ModuleCompletion', backref='submodule', lazy=True)

    # Ensure slug uniqueness per module
    __table_args__ = (
        db.UniqueConstraint('module_id', 'slug', name='unique_module_submodule_slug'),
    )


class ModuleCompletion(db.Model):
    __tablename__ = 'module_completions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    submodule_id = db.Column(db.Integer, db.ForeignKey('submodules.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Ensure uniqueness of user-submodule combination
    __table_args__ = (
        db.UniqueConstraint('user_id', 'submodule_id', name='unique_user_submodule'),
    )


class UserLog(db.Model):
    __tablename__ = 'user_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    additional_data = db.Column(db.Text, nullable=True)


class PaymentPlan(db.Model):
    __tablename__ = 'payment_plans'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    price_usd = db.Column(db.Integer, default=0)  # Price in cents (e.g., 1999 = $19.99)
    duration_days = db.Column(db.Integer, nullable=True)  # null for lifetime plans
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    payments = db.relationship('Payment', backref='plan', lazy=True)


class Payment(db.Model):
    __tablename__ = 'payments'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('payment_plans.id'), nullable=False)
    reference = db.Column(db.String(100), unique=True, nullable=False)
    amount = db.Column(db.Integer, default=0)  # Amount in cents
    status = db.Column(db.String(20), default='pending')  # 'pending', 'completed', 'failed', 'refunded'
    transaction_id = db.Column(db.String(100), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    retries = db.Column(db.Integer, default=0)
    verification_logs = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class EmailLog(db.Model):
    __tablename__ = 'email_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    email_type = db.Column(db.String(50), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    recipient = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'sent', 'failed'
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    additional_data = db.Column(db.Text, nullable=True)