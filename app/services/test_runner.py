from app.models import Event, Schema, TestRun, PayloadLog, db
from app.services.browser import BrowserSession
from app.services.validator import validate_payload
from datetime import datetime
import time
import json
import re
import fnmatch

def url_matches(captured_url, filter_value, match_type):
    if match_type == 'regex':
        return re.search(filter_value, captured_url) is not None
    elif match_type == 'glob':
        return fnmatch.fnmatch(captured_url, filter_value)
    else:  # exact
        return captured_url == filter_value

def run_tests_for_property(property_id, browser=None):
    test_run = TestRun(property_id=property_id)
    db.session.add(test_run)
    db.session.flush()

    events = Event.query.filter_by(property_id=property_id).all()

    browser_created = False
    if browser is None:
        browser = BrowserSession(headless=False)
        browser_created = True

    context = browser if browser_created else browser.__enter__()

    try:
        with context:
            for event in events:
                browser.visit(event.url)
                wait_time = event.wait_seconds if event.wait_seconds else 2
                time.sleep(wait_time)

                all_captured = browser.get_all_event_payloads()

                matched = False
                for captured_name, event_payload, full_payload in all_captured:
                    request_url = full_payload.get("url", "")

                    if not url_matches(request_url, event.request_url_filter, event.url_match_type):
                        continue

                    if (
                        captured_name == event.expected_event_name
                        and event_payload.get('type') == event.event_type
                    ):
                        matched = True
                        schema = event.schema
                        rules_to_use = schema.validation_rules or "[]"

                        is_valid, errors = validate_payload(event_payload, rules_to_use)

                        db.session.add(PayloadLog(
                            test_run_id=test_run.id,
                            event_id=event.id,
                            status='PASS' if is_valid else 'FAIL',
                            errors=json.dumps(errors or []),
                            payload=json.dumps(full_payload)
                        ))

                if not matched:
                    db.session.add(PayloadLog(
                        test_run_id=test_run.id,
                        event_id=event.id,
                        status='FAIL',
                        errors=json.dumps(['Expected event not found in network requests.']),
                        payload=''
                    ))
    finally:
        if browser_created:
            browser.__exit__(None, None, None)

    db.session.commit()
    return test_run.id
