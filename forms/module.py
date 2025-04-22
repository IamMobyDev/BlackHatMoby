# forms/module.py
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    TextAreaField,
    IntegerField,
    BooleanField,
    SubmitField,
    SelectField,
)
from wtforms.validators import DataRequired, Regexp


class CreateModuleForm(FlaskForm):
    """Form for creating a new module."""

    title = StringField("Title", validators=[DataRequired()])
    slug = StringField(
        "Slug",
        validators=[
            DataRequired(),
            Regexp(
                r"^[a-z0-9\-]+$",
                message="Slug can only contain lowercase letters, numbers, and dashes",
            ),
        ],
    )
    description = TextAreaField("Description")
    order = IntegerField("Display Order", default=0)
    trial_accessible = BooleanField("Available in Trial", default=False)
    submit = SubmitField("Create Module")


class CreateSubmoduleForm(FlaskForm):
    """Form for creating a new submodule."""

    module_id = SelectField("Module", coerce=int, validators=[DataRequired()])
    title = StringField("Title", validators=[DataRequired()])
    slug = StringField(
        "Slug",
        validators=[
            DataRequired(),
            Regexp(
                r"^[a-z0-9\-]+$",
                message="Slug can only contain lowercase letters, numbers, and dashes",
            ),
        ],
    )
    content = TextAreaField("Content (Markdown)", validators=[DataRequired()])
    order = IntegerField("Display Order", default=0)
    submit = SubmitField("Create Submodule")
