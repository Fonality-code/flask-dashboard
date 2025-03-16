from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request, current_app, make_response
from flask_login import login_required, current_user
from app.models.settings import Settings
from app.models.user import User, requires_roles  # Fixed import path
from app.forms.settings_form import UISettingsForm, ThemeColorsForm

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')

@settings_bp.route('/', methods=['GET'])
@login_required
@requires_roles('admin', 'system_admin')
def index():
    """Main settings page"""
    return render_template('settings/index.html')

@settings_bp.route('/ui', methods=['GET', 'POST'])
@login_required
@requires_roles('admin', 'system_admin')
def ui_settings():
    """UI settings page"""
    # Get current UI settings
    ui_settings = Settings.get_ui_settings()
    
    # Create form and populate with current settings
    form = UISettingsForm()
    
    # On POST: Save settings
    if form.validate_on_submit():
        if form.reset.data:
            # Reset to defaults by deleting the settings entry
            settings = Settings.query.filter_by(key='ui_settings').first()
            if settings:
                from app.extensions import db
                db.session.delete(settings)
                db.session.commit()
                flash('UI settings have been reset to defaults', 'success')
                return redirect(url_for('settings.ui_settings'))
                
        elif form.submit.data:
            # Process form data
            new_settings = {
                'general': {
                    'app-name': form.general.app_name.data,
                    'app-logo-url': form.general.app_logo_url.data,
                    'app-favicon-url': form.general.app_favicon_url.data,
                    'form-image-url': form.general.form_image_url.data,
                },
                'light': {
                    'primary-color': form.light_theme.primary_color.data,
                    'primary-hover': form.light_theme.primary_hover.data,
                    'secondary-color': form.light_theme.secondary_color.data,
                    'text-color': form.light_theme.text_color.data,
                    'light-text': form.light_theme.light_text.data,
                    'border-color': form.light_theme.border_color.data,
                    'background-color': form.light_theme.background_color.data,
                    'light-gray': form.light_theme.light_gray.data,
                    'warning-color': form.light_theme.warning_color.data,
                    'error-color': form.light_theme.error_color.data,
                },
                'dark': {
                    'primary-color': form.dark_theme.primary_color.data,
                    'primary-hover': form.dark_theme.primary_hover.data,
                    'secondary-color': form.dark_theme.secondary_color.data,
                    'text-color': form.dark_theme.text_color.data,
                    'light-text': form.dark_theme.light_text.data,
                    'border-color': form.dark_theme.border_color.data,
                    'background-color': form.dark_theme.background_color.data,
                    'light-gray': form.dark_theme.light_gray.data,
                    'warning-color': form.dark_theme.warning_color.data,
                    'error-color': form.dark_theme.error_color.data,
                }
            }
            
            try:
                # Save settings
                Settings.save_ui_settings(new_settings)
                flash('UI settings updated successfully! Refresh the page if changes are not immediately visible.', 'success')
                return redirect(url_for('settings.ui_settings'))
            except Exception as e:
                current_app.logger.error(f"Error saving UI settings: {str(e)}")
                flash(f'Error saving settings: {str(e)}', 'error')
    
    # For GET: Populate form with current values
    else:
        # Fill the form with current values
        if ui_settings:
            # Populate general settings
            if 'general' in ui_settings:
                for key, value in ui_settings['general'].items():
                    form_key = key.replace('-', '_')
                    if hasattr(form.general, form_key):
                        getattr(form.general, form_key).data = value
            
            # Map hyphenated keys to underscore keys for the form
            key_mapping = {
                'primary-color': 'primary_color',
                'primary-hover': 'primary_hover',
                'secondary-color': 'secondary_color',
                'text-color': 'text_color',
                'light-text': 'light_text',
                'border-color': 'border_color',
                'background-color': 'background_color',
                'light-gray': 'light_gray',
                'warning-color': 'warning_color',
                'error-color': 'error_color',
            }
            
            # Populate light theme
            for key, value in ui_settings['light'].items():
                form_key = key_mapping.get(key, key.replace('-', '_'))
                if hasattr(form.light_theme, form_key):
                    getattr(form.light_theme, form_key).data = value
                    
            # Populate dark theme
            for key, value in ui_settings['dark'].items():
                form_key = key_mapping.get(key, key.replace('-', '_'))
                if hasattr(form.dark_theme, form_key):
                    getattr(form.dark_theme, form_key).data = value
    
    return render_template('settings/ui_settings.html', form=form, ui_settings=ui_settings)

@settings_bp.route('/api/ui-settings', methods=['GET'])
def get_ui_settings_api():
    """API endpoint to get UI settings"""
    try:
        ui_settings = Settings.get_ui_settings()
        
        # Debug the settings before returning
        current_app.logger.info(f"Returning UI settings: {ui_settings}")
        
        # Set cache control headers to prevent caching
        response = make_response(jsonify(ui_settings))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        current_app.logger.error(f"Error fetching UI settings: {str(e)}")
        return jsonify({"error": str(e)}), 500
