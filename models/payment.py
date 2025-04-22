from datetime import datetime
from . import db


class PaymentPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    price_usd = db.Column(db.Integer, nullable=False)  # Stored in cents
    duration_days = db.Column(db.Integer, nullable=True)  # Null for lifetime plans
    is_active = db.Column(db.Boolean, default=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    payments = db.relationship("Payment", backref="plan", lazy=True)


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey("payment_plan.id"), nullable=False)
    reference = db.Column(db.String(100), unique=True, nullable=False)
    amount = db.Column(db.Integer, nullable=False)  # Stored in cents
    status = db.Column(db.String(20), nullable=False)  # pending, completed, failed
    transaction_id = db.Column(db.String(100), nullable=True)
    verification_logs = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    retries = db.Column(db.Integer, default=0)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
