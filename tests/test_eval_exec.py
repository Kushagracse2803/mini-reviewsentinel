from app.static_analysis import dangerous_eval


def test_eval_on_dynamic_input_is_high():
    source = "def handler(user_input):\n    return eval(user_input)\n"
    findings, error = dangerous_eval.analyze("handler.py", source)
    assert error is None
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"
    assert findings[0].rule_id == "EVALEXEC001"


def test_eval_on_literal_is_medium_not_high():
    source = "result = eval('1 + 1')\n"
    findings, error = dangerous_eval.analyze("calc.py", source)
    assert error is None
    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"


def test_exec_detected_too():
    source = "exec(command)\n"
    findings, error = dangerous_eval.analyze("runner.py", source)
    assert error is None
    assert len(findings) == 1
    assert "exec" in findings[0].finding.lower()
