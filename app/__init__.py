from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dotenv import load_dotenv
import os
import json

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    
    load_dotenv()

    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    migrate.init_app(app, db)

    from .routes import main
    app.register_blueprint(main)

    @app.context_processor
    def inject_current_user():
        from .models import User
        user_id = session.get('user_id')
        user = User.query.get(user_id) if user_id else None
        return dict(current_user=user)

    app.jinja_env.filters['loads'] = json.loads

    return app
