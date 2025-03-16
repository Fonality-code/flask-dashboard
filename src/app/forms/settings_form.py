from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FieldList, FormField, URLField
from wtforms.validators import DataRequired, Regexp, Optional, URL, Length

# Regular expression for valid hex color
hex_color_regex = r'^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$'

class GeneralSettingsForm(FlaskForm):
    """Form for general UI settings like app name and logo"""
    app_name = StringField('Application Name', validators=[
        DataRequired(),
        Length(min=1, max=50, message="App name must be between 1 and 50 characters")
    ])
    app_logo_url = URLField('Logo URL', validators=[
        Optional(),
        URL(message="Must be a valid URL or left empty for default logo")
    ])
    app_favicon_url = URLField('Favicon URL', validators=[
        Optional(),
        URL(message="Must be a valid URL or left empty for default favicon")
    ])
    form_image_url = URLField('Form Image URL', validators=[
        Optional(),
        URL(message="Must be a valid URL or left empty for default form image")
    ])
    
    # No CSRF token for this nested form
    class Meta:
        csrf = False

class ThemeColorsForm(FlaskForm):
    """Form for a single theme's colors (light or dark)"""
    primary_color = StringField('Primary Color', validators=[
        DataRequired(),
        Regexp(hex_color_regex, message="Must be a valid hex color (e.g. #6366F1)")
    ])
    primary_hover = StringField('Primary Hover', validators=[
        DataRequired(), 
        Regexp(hex_color_regex, message="Must be a valid hex color")
    ])
    secondary_color = StringField('Secondary Color', validators=[
        DataRequired(), 
        Regexp(hex_color_regex, message="Must be a valid hex color")
    ])
    text_color = StringField('Text Color', validators=[
        DataRequired(), 
        Regexp(hex_color_regex, message="Must be a valid hex color")
    ])
    light_text = StringField('Light Text', validators=[
        DataRequired(), 
        Regexp(hex_color_regex, message="Must be a valid hex color")
    ])
    border_color = StringField('Border Color', validators=[
        DataRequired(), 
        Regexp(hex_color_regex, message="Must be a valid hex color")
    ])
    background_color = StringField('Background Color', validators=[
        DataRequired(), 
        Regexp(hex_color_regex, message="Must be a valid hex color")
    ])
    light_gray = StringField('Light Gray', validators=[
        DataRequired(), 
        Regexp(hex_color_regex, message="Must be a valid hex color")
    ])
    warning_color = StringField('Warning Color', validators=[
        DataRequired(), 
        Regexp(hex_color_regex, message="Must be a valid hex color")
    ])
    error_color = StringField('Error Color', validators=[
        DataRequired(), 
        Regexp(hex_color_regex, message="Must be a valid hex color")
    ])
    
    # No CSRF token for this nested form
    class Meta:
        csrf = False

class UISettingsForm(FlaskForm):
    """Form for UI settings with light and dark themes"""
    general = FormField(GeneralSettingsForm, label='General Settings')
    light_theme = FormField(ThemeColorsForm, label='Light Theme')
    dark_theme = FormField(ThemeColorsForm, label='Dark Theme') 
    submit = SubmitField('Save Settings')
    reset = SubmitField('Reset to Defaults')
