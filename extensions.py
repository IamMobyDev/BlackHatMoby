
"""Flask extensions instance definitions"""

from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy

# Initialize extensions without binding to app
mail = Mail()
limiter = Limiter(get_remote_address)
csrf = CSRFProtect()
db = SQLAlchemy()
