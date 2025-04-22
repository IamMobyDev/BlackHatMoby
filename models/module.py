from datetime import datetime
from . import db


class Module(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    order = db.Column(db.Integer, default=0)
    trial_accessible = db.Column(db.Boolean, default=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    submodules = db.relationship(
        "Submodule", backref="module", lazy=True, order_by="Submodule.order"
    )


class Submodule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    module_id = db.Column(db.Integer, db.ForeignKey("module.id"), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), nullable=False)
    order = db.Column(db.Integer, default=0)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    completions = db.relationship("ModuleCompletion", backref="submodule", lazy=True)

    # Composite unique constraint for module_id + slug
    __table_args__ = (db.UniqueConstraint("module_id", "slug", name="_module_slug_uc"),)


class ModuleCompletion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    submodule_id = db.Column(db.Integer, db.ForeignKey("submodule.id"), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Unique constraint to prevent duplicate completions
    __table_args__ = (
        db.UniqueConstraint("user_id", "submodule_id", name="_user_submodule_uc"),
    )
