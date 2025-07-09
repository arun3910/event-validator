import json
import uuid
from dateutil.parser import isoparse

def get_nested(data, path):
    keys = path.split('.')
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data

def is_valid_format(value, fmt):
    if fmt == 'uuid':
        try:
            uuid.UUID(str(value))
            return True
        except:
            return False
    if fmt == 'date-time':
        try:
            isoparse(value)
            return True
        except:
            return False
    return True

def validate_payload(payload, rules_str):
    errors = []
    try:
        rules = json.loads(rules_str or "[]")
        for rule in rules:
            val = get_nested(payload, rule["path"])
            if val is None:
                if rule.get("required", True):
                    errors.append(f"Missing: {rule['path']}")
                continue
            if rule["type"] == "string" and not isinstance(val, str):
                errors.append(f"{rule['path']} must be string")
            elif rule["type"] == "number" and not isinstance(val, (int, float)):
                errors.append(f"{rule['path']} must be number")
            elif rule["type"] == "boolean" and not isinstance(val, bool):
                errors.append(f"{rule['path']} must be boolean")
            elif rule["type"] == "uuid" and not is_valid_format(val, "uuid"):
                errors.append(f"{rule['path']} invalid format: expected UUID")

            if rule.get("format") and not is_valid_format(val, rule["format"]):
                errors.append(f"{rule['path']} invalid format: expected {rule['format']}")
    except Exception as e:
        errors.append(f"Validation parsing error: {str(e)}")

    return len(errors) == 0, errors
