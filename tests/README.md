# RTSA tests

Regression coverage for defects found during maintenance audits. Each scenario pins a
bug that was reproduced before it was fixed, so the same failure cannot return silently.

Run with the stdlib only, from anywhere:

    python3 tests/test_audit_hardening.py

`test_audit_hardening.py` covers, in order: SQLite shutdown durability (the final
in-flight batch must be written, not cancelled), the drain mechanism that guarantees it,
ssh_monitor teardown draining in-flight enrichment tasks, its journald probe not
spawning an untimed subprocess, IncidentEngine evidence staying bounded and linear under
a high-cardinality scan, /sofix + /fixssl refusing vhost names that escape the configured
conf directory, EventBus routing after the dead category index was removed, and the
Discord reconnect backoff resetting after a stable session.
