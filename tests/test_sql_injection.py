from app.static_analysis import sql_injection


def test_fstring_sql_injection_detected():
    """The exact 'vulnerable' example from the assignment brief."""
    source = (
        "def get_user(cursor, user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    cursor.execute(query)\n"
    )
    findings, error = sql_injection.analyze("payments.py", source)
    assert error is None
    assert len(findings) == 1
    assert findings[0].rule_id == "SQLI001"
    assert findings[0].severity.value == "HIGH"
    assert findings[0].line == 3  # the cursor.execute(...) call site


def test_parameterized_query_not_flagged():
    """The exact 'safe' example from the assignment brief."""
    source = (
        "def get_user(cursor, user_id):\n"
        "    query = \"SELECT * FROM users WHERE id = ?\"\n"
        "    cursor.execute(query, (user_id,))\n"
    )
    findings, error = sql_injection.analyze("payments.py", source)
    assert error is None
    assert findings == []


def test_direct_inline_concatenation_detected():
    source = 'cursor.execute("SELECT * FROM t WHERE x = " + user_input)\n'
    findings, error = sql_injection.analyze("app.py", source)
    assert error is None
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"


def test_unparseable_file_reports_error_not_crash():
    findings, error = sql_injection.analyze("broken.py", "def f(:\n")
    assert findings == []
    assert error is not None
