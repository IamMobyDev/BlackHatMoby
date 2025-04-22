from flask import redirect, url_for, session, abort, request
from functools import wraps
from models import User

def login_required(view):
    """Decorator to require login for a route"""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login', next=request.path))
        return view(*args, **kwargs)
    return wrapped_view

def admin_required(view):
    """Decorator to require admin rights for a route"""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login', next=request.path))
            
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            abort(403)
            
        return view(*args, **kwargs)
    return wrapped_view

def subscription_required(view):
    """Decorator to require an active subscription for a route"""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login', next=request.path))
            
        user = User.query.get(session['user_id'])
        if not user:
            return redirect(url_for('auth.login'))
            
        # Admins can access everything
        if user.role == 'admin':
            return view(*args, **kwargs)
            
        # Check if user has an active subscription
        if not user.has_active_subscription():
            return redirect(url_for('payment.pricing', error="This content requires an active subscription"))
            
        return view(*args, **kwargs)
    return wrapped_view

def subscription_required(view):
    """Decorator to require an active subscription for a route"""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login', next=request.path))

        user = User.query.get(session['user_id'])
        if not user:
            return redirect(url_for('auth.login'))

        # Admins can access everything
        if user.role == 'admin':
            return view(*args, **kwargs)

        # Check if user has an active subscription
        if not user.has_active_subscription():
            return redirect(url_for('pricing', error="This content requires an active subscription"))

        # For specific module access, the view needs to do further checks with user.can_access_module()
        return view(*args, **kwargs)
    return wrapped_view