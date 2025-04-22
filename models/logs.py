from datetime import datetime
from . import db


class UserLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    email_type = db.Column(db.String(50), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    recipient = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # sent, failed
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
