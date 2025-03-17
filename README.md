# Dashboard

A Flask-based dashboard application.

## Overview

Dashboard is a web application built with Flask. It provides user authentication, Google OAuth integration, and dynamic UI settings. Logs are managed through a rotating file handler, and the project uses SQLAlchemy for the database operations.

## File Structure

- **src/**
  - **app/**
    - [`__init__.py`](src/app/__init__.py): Contains the [`create_app`](src/app/__init__.py) function which initializes the app, sets up logging, registers blueprints, and configures error handling.
    - Other directories such as `crud/`, `decorators/`, `forms/`, `logs/`, `models/`, `routes/`, `static/`, `templates/`, and `utils/`.
  - **config.py**: Configuration settings for the application.
- **main.py**: Entry point of the application.
- **pyproject.toml**: Project configuration and dependencies.
- **Makefile**: Build/install scripts and commands.
- **.gitignore**: Patterns for files to ignore in version control.

## Requirements

- Python 3.12 or later.
- Dependencies listed in [pyproject.toml](pyproject.toml).

## Setup

1. **Clone the repository:**
   ```sh
   git clone <repository-url>
   cd 
   ```

```
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

```

