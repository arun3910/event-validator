from . import db
from datetime import datetime
from sqlalchemy import Text

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('super_admin', 'admin', 'employee'), default='employee')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    base_url = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    events = db.relationship('Event', backref='property', cascade="all, delete-orphan")

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)

    name = db.Column(db.String(100), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    url_match_type = db.Column(db.Enum('exact', 'regex', 'glob'), default='exact')  # NEW FIELD
    expected_event_name = db.Column(db.String(100), nullable=False)
    request_url_filter = db.Column(db.String(255), nullable=False)
    wait_seconds = db.Column(db.Integer, default=2)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    schema = db.relationship('Schema', backref='event', uselist=False, cascade="all, delete-orphan")


class Schema(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    json_schema = db.Column(db.Text, nullable=True)
    validation_rules = db.Column(db.Text, nullable=True)

class TestRun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)

    property = db.relationship('Property')
    payload_logs = db.relationship('PayloadLog', backref='test_run', cascade="all, delete-orphan")

class PayloadLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_run_id = db.Column(db.Integer, db.ForeignKey('test_run.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    status = db.Column(db.Enum('PASS', 'FAIL'), nullable=False)
    errors = db.Column(db.Text)
    payload = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    event = db.relationship('Event')
