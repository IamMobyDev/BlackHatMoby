# forms/auth.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import (
    DataRequired,
    Email,
    Length,
    Regexp,
    EqualTo,
    ValidationError,
)


class LoginForm(FlaskForm):
    """User login form."""

    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Log In")


class RegistrationForm(FlaskForm):
    """User registration form."""

    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=25),
            Regexp(
                "^[A-Za-z][A-Za-z0-9_.]*$",
                0,
                "Usernames must start with a letter and can only contain letters, numbers, dots or underscores",
            ),
        ],
    )
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters long"),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match"),
        ],
    )
    submit = SubmitField("Register")

    # These validation methods will need to be connected to the database
    # The actual implementation will be updated when integrating with models
    def validate_username(self, username):
        """Check if username is already taken."""
        # This will be updated with the actual User model import
        from models import User

        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                "Username already taken. Please choose a different one."
            )

    def validate_email(self, email):
        """Check if email is already registered."""
        from models import User

        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                "Email already registered. Please use a different one."
            )
