"""Flask extensions instance definitions"""

from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

# Initialize extensions without binding to app
mail = Mail()
limiter = Limiter(get_remote_address)
csrf = CSRFProtect()

# These extensions will be bound to the app in app.py with:
# mail.init_app(app)
# limiter.init_app(app)
# csrf.init_app(app)
