
from flask import Flask, render_template
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta
import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure Flask app
app.config.update(
    SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URI', 'sqlite:///blackmoby.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=os.getenv('SECRET_KEY', 'dev_secret_key'),
    WTF_CSRF_SECRET_KEY=os.getenv('WTF_CSRF_SECRET_KEY', 'dev_csrf_key'),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    # Email settings
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True').lower() == 'true',
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER', 'noreply@blackmoby.com')
)

# Initialize extensions
from extensions import db, csrf, limiter, mail

db.init_app(app)
mail.init_app(app)
csrf.init_app(app)
limiter.init_app(app)

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('blackmoby')

# Register blueprints
from routes import register_blueprints
register_blueprints(app)

# Create content directory if it doesn't exist
os.makedirs('content/modules', exist_ok=True)

if __name__ == '__main__':
    # Start the server
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
