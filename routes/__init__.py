"""Route package initialization.

This package contains all the route blueprints for the BlackMoby application.
"""

from flask import Blueprint

# Import all blueprints
from .main import main_bp
from .auth import auth_bp
from .modules import modules_bp

from .admin import admin_bp

# List of all blueprints to register with the app
all_blueprints = [main_bp, auth_bp, modules_bp, payment_bp, admin_bp]


def register_blueprints(app):
    """Register all blueprints with the Flask application."""
    for blueprint in all_blueprints:
        app.register_blueprint(blueprint)
