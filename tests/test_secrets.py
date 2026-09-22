from app.static_analysis import secrets


def test_hardcoded_secret_detected():
    source = 'password = "SuperSecretValue123!"\n'
    findings, error = secrets.analyze("config.py", source)
    assert error is None
    assert len(findings) == 1
    assert findings[0].finding == "Hardcoded Secret"


def test_known_key_format_detected_regardless_of_variable_name():
    source = 'x = "AKIAIOSFODNN7EXAMPLE"\n'  # AWS's own public documentation example key
    findings, error = secrets.analyze("config.py", source)
    assert error is None
    assert any(f.rule_id == "SECRET_PATTERN" and f.severity.value == "HIGH" for f in findings)


def test_env_lookup_not_flagged():
    source = 'import os\napi_key = os.getenv("API_KEY")\n'
    findings, error = secrets.analyze("config.py", source)
    assert error is None
    assert findings == []


def test_field_label_not_flagged_as_secret():
    """'not every string resembling a password ... should automatically be
    reported as a secret' -- assignment Section 3."""
    source = 'password_field_name = "password"\n'
    findings, error = secrets.analyze("forms.py", source)
    assert error is None
    assert findings == []


def test_placeholder_value_not_flagged():
    source = 'api_key = "changeme"\n'
    findings, error = secrets.analyze("config.py", source)
    assert error is None
    assert findings == []
