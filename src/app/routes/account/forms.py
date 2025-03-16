from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Email

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number')
    submit = SubmitField('Update')

class UpdateUserOptionsForm(FlaskForm):
    first_name = StringField('First Name')
    last_name = StringField('Last Name')
    profile_image = StringField('Profile Image URL')
    submit = SubmitField('Update Options')
