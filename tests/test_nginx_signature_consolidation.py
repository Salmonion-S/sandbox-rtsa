import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.injection_signatures as injection_signatures
import modules.nginx_monitor as nginx_monitor
from core.datatypes import EventCategory


def main() -> None:
    assert nginx_monitor._WEB_ATTACK_SIGNATURES is injection_signatures.WEB_ATTACK_SIGNATURES, (
        "nginx_monitor.py must not keep its own copy of the web-attack signature list -- it must "
        "reference the exact same object as core/injection_signatures.py's canonical list, so the "
        "two can never drift out of sync"
    )
    print("Scenario 1 (nginx_monitor._WEB_ATTACK_SIGNATURES is the same object as the canonical injection_signatures list, not a copy) PASSED")

    assert nginx_monitor._SQLI_PATTERN_FULL is injection_signatures.SQLI_PATTERN_FULL
    assert nginx_monitor._SQLI_PATTERN_STRICT is injection_signatures.SQLI_PATTERN_STRICT
    print("Scenario 2 (SQLi full/strict patterns are shared objects, not duplicated regexes) PASSED")

    categories_present = {category for category, _pattern, _confidence in injection_signatures.WEB_ATTACK_SIGNATURES}
    expected = {
        EventCategory.WEB_ATTACK_SQLI, EventCategory.WEB_ATTACK_XSS, EventCategory.WEB_ATTACK_RCE,
        EventCategory.WEB_ATTACK_LFI, EventCategory.WEB_ATTACK_PATH_TRAVERSAL, EventCategory.WEB_ATTACK_SCAN,
    }
    assert categories_present == expected, f"canonical list must retain full prior coverage: {categories_present}"
    print("Scenario 3 (canonical list retains all 6 pre-consolidation attack categories -- no coverage loss) PASSED")

    payloads = [
        ("/?id=1' UNION SELECT username,password FROM users--", EventCategory.WEB_ATTACK_SQLI),
        ("/?q=<script>alert(1)</script>", EventCategory.WEB_ATTACK_XSS),
        ("/?f=php://filter/convert.base64-encode/resource=index.php", EventCategory.WEB_ATTACK_LFI),
        ("/../../etc/passwd", EventCategory.WEB_ATTACK_PATH_TRAVERSAL),
        ("/.env", EventCategory.WEB_ATTACK_SCAN),
    ]
    for path, expected_category in payloads:
        matched = [
            category for category, pattern, _confidence in nginx_monitor._WEB_ATTACK_SIGNATURES
            if pattern.search(path)
        ]
        assert expected_category in matched, (
            f"nginx_monitor's signature list (sourced from the canonical module) must still classify "
            f"{path!r} as {expected_category}, got {matched}"
        )
        matched_via_canonical = [
            category for category, pattern, _confidence in injection_signatures.WEB_ATTACK_SIGNATURES
            if pattern.search(path)
        ]
        assert matched == matched_via_canonical, (
            f"classification via nginx_monitor's reference and the canonical module must be identical "
            f"for {path!r} -- any divergence here would mean the two are not truly the same source"
        )
    print(f"Scenario 4 ({len(payloads)} representative payloads classify identically whether read through nginx_monitor or the canonical injection_signatures module) PASSED")

    print("\nALL NGINX SIGNATURE CONSOLIDATION TESTS PASSED")


main()
