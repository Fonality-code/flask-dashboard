from datetime import datetime
from sqlalchemy.dialects.postgresql import JSON
from app.extensions import db
import json

class Settings(db.Model):
    __tablename__ = 'settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    @classmethod
    def get_ui_settings(cls):
        """Get UI settings or return default values"""
        settings = cls.query.filter_by(key='ui_settings').first()
        
        if not settings:
            # Default UI settings
            default_settings = {
                'general': {
                    'app-name': 'Dashboard',
                    'app-logo-url': '',  # Empty string for default logo
                    'app-favicon-url': '',  # Empty string for default favicon
                    'form-image-url': '',  # Empty string for default form image
                },
                'light': {
                    'primary-color': '#6366F1',
                    'primary-hover': '#4F46E5',
                    'secondary-color': '#10B981',
                    'text-color': '#111827',
                    'light-text': '#6B7280',
                    'border-color': '#E5E7EB',
                    'background-color': '#F9FAFB',
                    'light-gray': '#F3F4F6',
                    'warning-color': '#F59E0B',
                    'error-color': '#EF4444',
                },
                'dark': {
                    'primary-color': '#818CF8',
                    'primary-hover': '#A5B4FC',
                    'secondary-color': '#34D399',
                    'text-color': '#D1D5DB',
                    'light-text': '#9CA3AF',
                    'border-color': '#4B5563',
                    'background-color': '#111827',
                    'light-gray': '#1F2A44',
                    'warning-color': '#FBBF24',
                    'error-color': '#F87171',
                }
            }
            return default_settings
        
        try:
            if isinstance(settings.value, str):
                return json.loads(settings.value)
            return settings.value
        except Exception as e:
            print(f"Error parsing UI settings: {str(e)}")
            # Return defaults in case of error
            return cls.get_default_ui_settings()

    @classmethod
    def get_default_ui_settings(cls):
        """Get default UI settings - using consistent names with hyphens instead of underscores"""
        return {
            'general': {
                'app-name': 'Dashboard',
                'app-logo-url': '',  # Empty string for default logo
                'app-favicon-url': '',  # Empty string for default favicon
                'form-image-url': '',  # Empty string for default form image
            },
            'light': {
                'primary-color': '#6366F1',
                'primary-hover': '#4F46E5',
                'secondary-color': '#10B981',
                'text-color': '#111827',
                'light-text': '#6B7280',
                'border-color': '#E5E7EB',
                'background-color': '#F9FAFB',
                'light-gray': '#F3F4F6',
                'warning-color': '#F59E0B',
                'error-color': '#EF4444',
            },
            'dark': {
                'primary-color': '#818CF8',
                'primary-hover': '#A5B4FC',
                'secondary-color': '#34D399',
                'text-color': '#D1D5DB',
                'light-text': '#9CA3AF',
                'border-color': '#4B5563',
                'background-color': '#111827',
                'light-gray': '#1F2A44',
                'warning-color': '#FBBF24',
                'error-color': '#F87171',
            }
        }

    @classmethod
    def save_ui_settings(cls, settings_data):
        """Save UI settings"""
        try:
            settings = cls.query.filter_by(key='ui_settings').first()
            
            if settings:
                settings.value = settings_data
                settings.updated_at = datetime.now()
            else:
                settings = cls(key='ui_settings', value=settings_data)
                db.session.add(settings)
                
            db.session.commit()
            return settings
        except Exception as e:
            db.session.rollback()
            raise e
