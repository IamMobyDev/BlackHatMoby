
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    subscription = db.relationship('Subscription', backref='user', uselist=False)
    progress = db.relationship('ModuleProgress', backref='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def can_access_module(self, module):
        if not self.subscription or not self.subscription.is_active():
            return module.trial_accessible
        return self.subscription.plan_type in ['yearly', 'lifetime']

    def can_access_labs(self):
        return self.subscription and self.subscription.is_active() and self.subscription.plan_type != 'trial'

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    plan_type = db.Column(db.String(20), nullable=False)  # trial, yearly, lifetime
    start_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)
    active = db.Column(db.Boolean, default=True)

    def is_active(self):
        if not self.active:
            return False
        if self.plan_type == 'lifetime':
            return True
        return datetime.utcnow() <= self.end_date

class Module(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    order = db.Column(db.Integer, default=0)
    trial_accessible = db.Column(db.Boolean, default=False)
    has_lab = db.Column(db.Boolean, default=False)
    lab_file = db.Column(db.String(200))
    submodules = db.relationship('Submodule', backref='module', order_by='Submodule.order')

class Submodule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    module_id = db.Column(db.Integer, db.ForeignKey('module.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text)
    order = db.Column(db.Integer, default=0)

class ModuleProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    module_id = db.Column(db.Integer, db.ForeignKey('module.id'), nullable=False)
    submodule_id = db.Column(db.Integer, db.ForeignKey('submodule.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    plan_type = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='pending')
    payment_date = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_id = db.Column(db.String(100), unique=True)
