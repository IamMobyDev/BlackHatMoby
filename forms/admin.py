# forms/admin.py
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    TextAreaField,
    FloatField,
    IntegerField,
    BooleanField,
    SubmitField,
    SelectField,
)
from wtforms.validators import DataRequired, Optional


class PaymentPlanForm(FlaskForm):
    """Form for creating/editing a payment plan."""

    name = StringField("Name", validators=[DataRequired()])
    slug = StringField("Slug", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[DataRequired()])
    price_usd = FloatField("Price (USD)", validators=[DataRequired()])
    duration_days = IntegerField("Duration (Days)", validators=[Optional()])
    is_active = BooleanField("Active", default=True)
    submit = SubmitField("Submit")


class UserAdminForm(FlaskForm):
    """Form for admin editing of user properties."""

    role = SelectField("Role", choices=[("user", "User"), ("admin", "Admin")])
    subscription_status = SelectField(
        "Subscription Status",
        choices=[
            ("none", "None"),
            ("trial", "Trial"),
            ("active", "Active"),
            ("expired", "Expired"),
        ],
    )
    subscription_type = StringField("Subscription Type")
    subscription_end = StringField("Subscription End Date")
    submit = SubmitField("Update User")
