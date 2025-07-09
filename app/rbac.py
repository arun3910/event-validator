from flask import session, redirect, url_for, flash
from functools import wraps

def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session or 'role' not in session:
                flash("Login required", "danger")
                return redirect(url_for('main.login'))

            if session.get('role') not in roles:
                flash("Access denied.", "warning")
                return redirect(url_for('main.dashboard'))

            return f(*args, **kwargs)
        return decorated_function
    return wrapper
