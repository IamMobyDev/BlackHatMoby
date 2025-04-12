from flask import Flask, render_template, request, redirect, url_for, session, abort
import os

app = Flask(__name__)
app.secret_key = 'super-secret-key'  # replace with env var or secure method

# Dummy user database
USERS = {
    "admin@example.com": {"password": "adminpass", "role": "admin"},
    "user@example.com": {"password": "userpass", "role": "free"}
}

# Dummy module list (would come from DB later)
MODULES = [
    {"id": 1, "slug": "intro-to-electronics", "title": "Intro to Electronics", "premium": False},
    {"id": 2, "slug": "rfid-attacks", "title": "RFID Attacks", "premium": True},
]

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = USERS.get(email)
        if user and user['password'] == password:
            session['user'] = email
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', modules=MODULES)

@app.route('/modules/<slug>')
def view_module(slug):
    if 'user' not in session:
        return redirect(url_for('login'))
    module = next((m for m in MODULES if m['slug'] == slug), None)
    if not module:
        abort(404)
    if module['premium'] and session.get('role') != 'admin':
        return redirect(url_for('subscribe'))
    return render_template('module_view.html', module=module)

@app.route('/subscribe')
def subscribe():
    return render_template('subscribe.html')

@app.route('/admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        abort(403)
    return render_template('admin_dashboard.html', modules=MODULES)

if __name__ == '__main__':
    app.run(debug=True)
