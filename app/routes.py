from flask import Blueprint, render_template, request, redirect, url_for, flash, session, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash
from .models import db, User, Property, Event, Schema, TestRun, PayloadLog
from .rbac import role_required
from sqlalchemy.exc import IntegrityError
from app.services.test_runner import run_tests_for_property
from sqlalchemy import text
from app.services.browser import BrowserSession
import time
import json

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return redirect(url_for('main.login'))

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('main.dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@main.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.login'))

@main.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    if session['role'] == 'employee':
        return render_template('dashboard_employee.html')

    total_properties = Property.query.count()
    total_events = Event.query.count()
    total_test_runs = TestRun.query.count()
    total_failed_events = PayloadLog.query.filter_by(status='FAIL').count()

    return render_template(
        'dashboard.html',
        total_properties=total_properties,
        total_events=total_events,
        total_test_runs=total_test_runs,
        total_failed_events=total_failed_events
    )


@main.route('/users')
@role_required('super_admin')
def users():
    users = User.query.order_by(User.id.desc()).all()
    return render_template('users.html', users=users)

@main.route('/users/add', methods=['GET', 'POST'])
@role_required('super_admin')
def add_user():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('main.add_user'))
        new_user = User(
            name=request.form['name'],
            username=request.form['username'],
            password=generate_password_hash(request.form['password']),
            role=request.form['role']
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully.', 'success')
        return redirect(url_for('main.users'))
    return render_template('add_user.html')

@main.route('/users/promote/<int:user_id>')
@role_required('super_admin')
def promote_user(user_id):
    if 'user_id' not in session or session.get('role') != 'super_admin':
        flash('Access denied', 'danger')
        return redirect(url_for('main.dashboard'))

    user = User.query.get_or_404(user_id)
    if user.role == 'employee':
        user.role = 'admin'
        db.session.commit()
        flash(f'{user.username} promoted to Admin.', 'success')
    return redirect(url_for('main.users'))

@main.route('/users/demote/<int:user_id>')
@role_required('super_admin')
def demote_user(user_id):
    if 'user_id' not in session or session.get('role') != 'super_admin':
        flash('Access denied', 'danger')
        return redirect(url_for('main.dashboard'))

    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        user.role = 'employee'
        db.session.commit()
        flash(f'{user.username} demoted to Employee.', 'warning')
    return redirect(url_for('main.users'))

@main.route('/users/delete/<int:user_id>')
@role_required('super_admin')
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'super_admin':
        flash('Access denied', 'danger')
        return redirect(url_for('main.dashboard'))

    user = User.query.get_or_404(user_id)
    if user.role != 'super_admin':
        db.session.delete(user)
        db.session.commit()
        flash(f'{user.username} deleted.', 'danger')
    return redirect(url_for('main.users'))

@main.route('/properties')
@role_required('admin', 'super_admin')
def properties():
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    props = Property.query.order_by(Property.id.desc()).all()
    return render_template('properties.html', properties=props)

@main.route('/properties/add', methods=['GET', 'POST'])
@role_required('admin', 'super_admin')
def add_property():
    if request.method == 'POST':
        name = request.form['name']
        base_url = request.form['base_url']
        prop = Property(name=name, base_url=base_url)
        db.session.add(prop)
        try:
            db.session.commit()
            flash('Property added successfully.', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Property name already exists.', 'danger')
        return redirect(url_for('main.properties'))
    return render_template('add_property.html')

@main.route('/properties/delete/<int:prop_id>')
@role_required('admin', 'super_admin')
def delete_property(prop_id):
    prop = Property.query.get_or_404(prop_id)
    db.session.delete(prop)
    db.session.commit()
    flash('Property deleted.', 'danger')
    return redirect(url_for('main.properties'))

@main.route('/events')
@role_required('admin', 'super_admin')
def events():
    events = Event.query.order_by(Event.id.desc()).all()
    return render_template('events.html', events=events)

@main.route('/events/add', methods=['GET', 'POST'])
@role_required('admin', 'super_admin')
def add_event():
    properties = Property.query.all()
    if request.method == 'POST':
        name = request.form['name']
        event_type = request.form['event_type']
        url = request.form['url']
        expected_event_name = request.form['expected_event_name']
        wait_seconds = request.form.get('wait_seconds') or 2
        property_id = request.form['property_id']
        request_url_filter = request.form['request_url_filter']
        json_schema = request.form['json_schema']
        validation_rules = request.form.get('validation_rules', '')
        url_match_type = request.form.get('url_match_type', 'exact')

        event = Event(
            name=name,
            event_type=event_type,
            url=url,
            url_match_type=url_match_type,
            expected_event_name=expected_event_name,
            property_id=property_id,
            request_url_filter=request_url_filter,
            wait_seconds=int(wait_seconds)
        )
        db.session.add(event)
        db.session.flush()

        schema = Schema(
            event_id=event.id,
            json_schema=json_schema,
            validation_rules=validation_rules
        )
        db.session.add(schema)
        db.session.commit()
        flash('Event added successfully!', 'success')
        return redirect(url_for('main.events'))

    return render_template('event_form.html', event=None, properties=properties)


@main.route('/events/edit/<int:event_id>', methods=['GET', 'POST'])
@role_required('admin', 'super_admin')
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    properties = Property.query.all()
    if request.method == 'POST':
        event.name = request.form['name']
        event.event_type = request.form['event_type']
        event.url = request.form['url']
        event.url_match_type = request.form.get('url_match_type', 'exact')
        event.expected_event_name = request.form['expected_event_name']
        event.wait_seconds = int(request.form.get('wait_seconds') or 2)
        event.request_url_filter = request.form['request_url_filter']
        event.property_id = request.form['property_id']
        event.schema.json_schema = request.form['json_schema']
        event.schema.validation_rules = request.form.get('validation_rules', '')
        db.session.commit()
        flash('Event updated successfully!', 'success')
        return redirect(url_for('main.events'))

    return render_template('event_form.html', event=event, properties=properties)

@main.route('/events/delete/<int:event_id>', methods=['POST'])
@role_required('admin', 'super_admin')
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    db.session.delete(event)
    db.session.commit()
    flash('Event deleted.', 'danger')
    return redirect(url_for('main.events'))

@main.route('/tests')
@role_required('admin', 'super_admin')
def test_runs():
    runs = TestRun.query.order_by(TestRun.started_at.desc()).all()
    return render_template('test_run.html', runs=runs)

# Global dictionary to store matched requests temporarily per property_id
matched_requests = {}

@main.route('/tests/run', methods=['GET', 'POST'])
@role_required('admin', 'super_admin')
def run_test():
    properties = Property.query.all()

    if request.method == 'POST':
        property_id = request.form['property_id']
        property = Property.query.get(property_id)

        if not property:
            flash("Property not found", "danger")
            return redirect(url_for('main.run_test'))

        event = Event.query.filter_by(property_id=property_id).first()
        if not event:
            flash("No event configured for this property", "warning")
            return redirect(url_for('main.run_test'))

        from app.services.browser import BrowserSession  # Ensure correct path
        with BrowserSession(headless=False) as browser:
            # Set matcher only for the first event to capture real-time log
            browser.set_request_matcher(event.request_url_filter, event.url_match_type)

            # Visit the page and wait
            browser.visit(event.url)
            time.sleep(event.wait_seconds or 5)
            browser.get_all_event_payloads()

            # Save the matched request for streaming logs
            matched_requests[property_id] = browser.get_matched_request_details()

            # Run the full test for all events using the same browser instance
            run_id = run_tests_for_property(property_id, browser=browser)

        flash("Test executed.", "success")
        return redirect(url_for('main.test_results', run_id=run_id))

    return render_template('run_test.html', properties=properties)



@main.route('/stream-logs')
def stream_logs():
    property_id = request.args.get('property_id')

    def event_stream():
        for _ in range(10):  # retry window of ~10 seconds
            if property_id in matched_requests and matched_requests[property_id]:
                data = matched_requests[property_id]
                data = matched_requests.pop(property_id)  # Remove after streaming
                yield f"data: {json.dumps(data)}\n\n"
                break
            time.sleep(1)
        else:
            yield f"data: {json.dumps({'status': 'No matching request yet'})}\n\n"

    return Response(stream_with_context(event_stream()), mimetype='text/event-stream')


@main.route('/test-runs/<int:run_id>/results')
@role_required('admin', 'super_admin')
def test_results(run_id):
    run = TestRun.query.get_or_404(run_id)
    logs = run.payload_logs

    # Preprocess logs to safely decode payload and errors
    for log in logs:
        try:
            log.payload_json = json.loads(log.payload) if log.payload else None
        except Exception:
            log.payload_json = None

        try:
            log.error_list = json.loads(log.errors) if log.errors else []
        except Exception:
            log.error_list = [log.errors] if log.errors else []

    return render_template('test_results.html', run=run, logs=logs)


@main.route('/admin/reset', methods=['POST'])
@role_required('super_admin')
def reset_all_data():
    try:
        # Disable foreign key checks temporarily
        db.session.execute(text('SET FOREIGN_KEY_CHECKS = 0;'))

        # Loop through all tables except 'users'
        meta = db.metadata
        for table in reversed(meta.sorted_tables):
            if table.name != 'users':
                db.session.execute(text(f'TRUNCATE TABLE `{table.name}`;'))

        db.session.execute(text('SET FOREIGN_KEY_CHECKS = 1;'))
        db.session.commit()
        flash('All data (except users) has been reset.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error during reset: {e}', 'danger')
    
    return redirect(url_for('main.dashboard'))