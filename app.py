from flask import Flask, render_template, redirect, url_for, request, session, abort, flash, jsonify
import markdown
import os
import re
import json
import time
import hmac
import hashlib
import requests
import logging
import uuid
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, BooleanField, SelectField, IntegerField
from wtforms.validators import DataRequired, Regexp, Email, Length, EqualTo, ValidationError
from models import db, User, Module, Submodule, ModuleCompletion, UserLog, PaymentPlan, Payment, EmailLog
import functools
from flask_mail import Mail, Message
import threading

app = Flask(__name__)
app.config.from_object(os.environ.get('APP_SETTINGS'))
load_dotenv()
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "10 per hour"]
)
csrf = CSRFProtect(app)
mail = Mail(app)
db.init_app(app)

# Authentication decorator
def auth_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Admin decorator
def admin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# ... (rest of the app.py file would go here) ...

@app.route('/admin/modules')
@admin_required
def admin_modules():
    """Admin module management"""
    modules = Module.query.order_by(Module.order).all()
    form = CreateModuleForm()
    return render_template('admin/modules.html', modules=modules, form=form)

@app.route('/admin/modules/create', methods=['POST'])
@admin_required
def create_module():
    """Create a new module"""
    form = CreateModuleForm()
    if form.validate_on_submit():
        module = Module(
            title=form.title.data,
            slug=form.slug.data,
            description=form.description.data,
            order=form.order.data,
            trial_accessible=form.trial_accessible.data
        )
        db.session.add(module)
        db.session.commit()
        flash('Module created successfully', 'success')
        return redirect(url_for('admin_modules'))
    return redirect(url_for('admin_modules'))

@app.route('/admin/modules/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_module(id):
    """Edit an existing module"""
    module = Module.query.get_or_404(id)
    if request.method == 'POST':
        module.title = request.form.get('title')
        module.description = request.form.get('description')
        module.order = int(request.form.get('order', 0))
        module.trial_accessible = bool(request.form.get('trial_accessible'))
        db.session.commit()
        flash('Module updated successfully', 'success')
        return redirect(url_for('admin_modules'))
    return render_template('edit_module.html', module=module)

@app.route('/admin/modules/<int:id>/delete', methods=['POST'])
@admin_required
def delete_module(id):
    """Delete a module"""
    module = Module.query.get_or_404(id)
    db.session.delete(module)
    db.session.commit()
    flash('Module deleted successfully', 'success')
    return redirect(url_for('admin_modules'))


class CreateModuleForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    slug = StringField('Slug', validators=[DataRequired(), Regexp(r'^[a-z0-9-]+$')])
    description = TextAreaField('Description', validators=[DataRequired()])
    order = IntegerField('Order', validators=[DataRequired()])
    trial_accessible = BooleanField('Trial Accessible')
    submit = SubmitField('Create Module')

    def validate_slug(self, field):
        if Module.query.filter_by(slug=field.data).first():
            raise ValidationError('Slug already in use.')


if __name__ == '__main__':
    app.run(debug=True)