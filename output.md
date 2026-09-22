```
(mini-reviewsentinel) PS C:\Users\kushagra\Desktop\CSAI\mini-reviewsentinel> uv pip install -r requirements.txt
Checked 9 packages in 23ms
(mini-reviewsentinel) PS C:\Users\kushagra\Desktop\CSAI\mini-reviewsentinel> pytest -v
========================================== test session starts ==========================================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.6.0 -- C:\Users\kushagra\Desktop\CSAI\mini-reviewsentinel\.venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\kushagra\Desktop\CSAI\mini-reviewsentinel
configfile: pyproject.toml
plugins: anyio-4.15.1
collected 29 items                                                                                       

tests/test_agent_retry_limit.py::test_agent_stops_at_max_iterations PASSED                         [  3%]
tests/test_agent_retry_limit.py::test_agent_stops_early_when_llm_becomes_confident PASSED          [  6%]
tests/test_api.py::test_health PASSED                                                              [ 10%]
tests/test_api.py::test_review_without_llm_configured_falls_back_to_static_only PASSED             [ 13%]
tests/test_api.py::test_empty_files_rejected_with_400 PASSED                                       [ 17%]
tests/test_conflict_resolution.py::test_static_high_llm_low_static_wins PASSED                     [ 20%]
tests/test_conflict_resolution.py::test_static_low_llm_high_capped_at_review_required PASSED       [ 24%]
tests/test_conflict_resolution.py::test_both_agree_low_is_approved PASSED                          [ 27%]
tests/test_conflict_resolution.py::test_both_agree_high_is_rejected PASSED                         [ 31%]
tests/test_eval_exec.py::test_eval_on_dynamic_input_is_high PASSED                                 [ 34%]
tests/test_eval_exec.py::test_eval_on_literal_is_medium_not_high PASSED                            [ 37%]
tests/test_eval_exec.py::test_exec_detected_too PASSED                                             [ 41%]
tests/test_hidden_cases.py::test_hidden_case_1_secret_via_indirection_not_flagged PASSED           [ 44%]
tests/test_hidden_cases.py::test_hidden_case_2_prompt_injection_split_across_lines_detected PASSED [ 48%]
tests/test_hidden_cases.py::test_hidden_case_3_reused_request_id_with_different_content_conflicts PASSED [ 51%]
tests/test_llm_reliability.py::test_malformed_llm_output_does_not_crash PASSED                     [ 55%]
tests/test_llm_reliability.py::test_llm_unavailable_is_handled_not_raised PASSED                   [ 58%]
tests/test_llm_reliability.py::test_json_wrapped_in_markdown_fence_is_recovered PASSED             [ 62%]
tests/test_prompt_injection.py::test_prompt_injection_in_comment_detected PASSED                   [ 65%]
tests/test_prompt_injection.py::test_normal_comment_not_flagged PASSED                             [ 68%]
tests/test_secrets.py::test_hardcoded_secret_detected PASSED                                       [ 72%]
tests/test_secrets.py::test_known_key_format_detected_regardless_of_variable_name PASSED           [ 75%]
tests/test_secrets.py::test_env_lookup_not_flagged PASSED                                          [ 79%]
tests/test_secrets.py::test_field_label_not_flagged_as_secret PASSED                               [ 82%]
tests/test_secrets.py::test_placeholder_value_not_flagged PASSED                                   [ 86%]
tests/test_sql_injection.py::test_fstring_sql_injection_detected PASSED                            [ 89%]
tests/test_sql_injection.py::test_parameterized_query_not_flagged PASSED                           [ 93%]
tests/test_sql_injection.py::test_direct_inline_concatenation_detected PASSED                      [ 96%]
tests/test_sql_injection.py::test_unparseable_file_reports_error_not_crash PASSED                  [100%]

=========================================== warnings summary ============================================
.venv\Lib\site-packages\starlette\testclient.py:53
  C:\Users\kushagra\Desktop\CSAI\mini-reviewsentinel\.venv\Lib\site-packages\starlette\testclient.py:53: DeprecationWarning: The anyio.abc.BlockingPortal alias is deprecated, use anyio.from_thread.BlockingPortal instead.
    _PortalFactoryType = Callable[[], AbstractContextManager[anyio.abc.BlockingPortal]]

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
===================================== 29 passed, 1 warning in 2.41s =====================================
(mini-reviewsentinel) PS C:\Users\kushagra\Desktop\CSAI\mini-reviewsentinel> python -m app.main examples/vulnerable_payments.py 
                                     Mini ReviewSentinel -- REJECTED                                      
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ File                 ┃ Line ┃ Finding              ┃ Severity ┃ Source          ┃ Recommendation       ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ examples\vulnerable… │ 11   │ SQL Injection        │ HIGH     │ static_analysis │ Use a parameterized  │
│                      │      │                      │          │                 │ query: pass SQL text │
│                      │      │                      │          │                 │ as a plain string    │
│                      │      │                      │          │                 │ with placeholders    │
│                      │      │                      │          │                 │ (e.g. `?` or `%s`)   │
│                      │      │                      │          │                 │ and supply values as │
│                      │      │                      │          │                 │ a separate argument, │
│                      │      │                      │          │                 │ e.g.                 │
│                      │      │                      │          │                 │ cursor.execute("SEL… │
│                      │      │                      │          │                 │ * FROM t WHERE id =  │
│                      │      │                      │          │                 │ ?", (value,)).       │
│ examples\vulnerable… │ 6    │ Hardcoded Secret     │ HIGH     │ static_analysis │ Load this value from │
│                      │      │                      │          │                 │ an environment       │
│                      │      │                      │          │                 │ variable or a        │
│                      │      │                      │          │                 │ secrets manager      │
│                      │      │                      │          │                 │ instead of           │
│                      │      │                      │          │                 │ committing it to     │
│                      │      │                      │          │                 │ source.              │
│ examples\vulnerable… │ 22   │ Dangerous use of     │ HIGH     │ static_analysis │ Avoid `eval()`       │
│                      │      │ eval()               │          │                 │ entirely. Use        │
│                      │      │                      │          │                 │ `ast.literal_eval()` │
│                      │      │                      │          │                 │ for parsing literal  │
│                      │      │                      │          │                 │ data, or an explicit │
│                      │      │                      │          │                 │ parser/dispatch      │
│                      │      │                      │          │                 │ table for anything   │
│                      │      │                      │          │                 │ more dynamic.        │
│ examples\vulnerable… │ 3    │ Prompt Injection     │ HIGH     │ static_analysis │ Remove text designed │
│                      │      │ Attempt              │          │                 │ to influence an      │
│                      │      │                      │          │                 │ automated reviewer.  │
│                      │      │                      │          │                 │ Comments and strings │
│                      │      │                      │          │                 │ in source code are   │
│                      │      │                      │          │                 │ never treated as     │
│                      │      │                      │          │                 │ instructions by this │
│                      │      │                      │          │                 │ system, but their    │
│                      │      │                      │          │                 │ presence is itself a │
│                      │      │                      │          │                 │ red flag worth a     │
│                      │      │                      │          │                 │ human look.          │
│ examples\vulnerable… │ 4    │ Prompt Injection     │ HIGH     │ static_analysis │ Remove text designed │
│                      │      │ Attempt              │          │                 │ to influence an      │
│                      │      │                      │          │                 │ automated reviewer.  │
│                      │      │                      │          │                 │ Comments and strings │
│                      │      │                      │          │                 │ in source code are   │
│                      │      │                      │          │                 │ never treated as     │
│                      │      │                      │          │                 │ instructions by this │
│                      │      │                      │          │                 │ system, but their    │
│                      │      │                      │          │                 │ presence is itself a │
│                      │      │                      │          │                 │ red flag worth a     │
│                      │      │                      │          │                 │ human look.          │
└──────────────────────┴──────┴──────────────────────┴──────────┴─────────────────┴──────────────────────┘
Overall decision: REJECTED
Note: LLM review was unavailable or unusable for at least one file; decision falls back to static analysis for that file.
(mini-reviewsentinel) PS C:\Users\kushagra\Desktop\CSAI\mini-reviewsentinel>
```
