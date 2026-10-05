import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.injection_signatures import classify_request

REPORTED_FP_QUERY = (
    "/search?q=Multiple+Choice+Question%3A+During+excitation+of+a+muscle+"
    "fiber%2C+the+sarcolemma+becomes+depolarized.%0D%0AWhich+of+the+"
    "following+best+describes+this+process%3F%0D%0AA.+Calcium+influx"
)


def rules_hit(result):
    return set(result.rules)


def main():
    result = classify_request("GET", REPORTED_FP_QUERY, user_agent="Mozilla/5.0 (compatible; bingbot/2.0)")
    assert "crlf_encoded_newline" not in rules_hit(result), (
        f"free-text search query with an embedded real newline must not trip CRLF Injection: {result}"
    )
    print("Scenario 1 (reported FP: bank-soal search query with %0D%0A line breaks -- no CRLF alert) PASSED")

    multi_paragraph = "/search?q=First+paragraph+of+text.%0D%0ASecond+paragraph+continues+here.%0D%0AThird+line."
    result2 = classify_request("GET", multi_paragraph)
    assert "crlf_encoded_newline" not in rules_hit(result2), (
        f"multiple embedded %0D%0A line breaks in free text still must not alert: {result2}"
    )
    print("Scenario 2 (multiple %0D%0A line breaks scattered through plain text -- still no alert) PASSED")

    for label, payload in (
        ("Set-Cookie header injection", "/redirect?url=http://x.com%0d%0aSet-Cookie:%20admin=1"),
        ("Location header injection", "/redirect?url=http://x.com%0d%0aLocation:%20http://evil.com"),
        ("arbitrary header name, encoded colon", "/x?p=1%0d%0aX-Injected-Header%3a%20evil"),
        ("header name padded with encoded space", "/x?p=1%0d%0a%20X-Injected:%20evil"),
        ("doubled CRLF, response-splitting terminator", "/x?p=1%0d%0a%0d%0a<script>evil</script>"),
        ("CR-CR anomaly", "/x?p=1%0d%0d2"),
        ("LF-CR anomaly", "/x?p=1%0a%0d2"),
    ):
        r = classify_request("GET", payload)
        assert "crlf_encoded_newline" in rules_hit(r), f"{label}: real CRLF injection payload must still alert: {r}"
    print("Scenario 3 (7 real CRLF/header-injection payload shapes -- all still detected) PASSED")

    smuggle_payload = "/redirect?url=http://x.com%0d%0aSet-Cookie:%20admin=1"
    r = classify_request("GET", smuggle_payload)
    assert "crlf_header_smuggle" in rules_hit(r), f"crlf_header_smuggle must be unaffected by this change: {r}"
    print("Scenario 4 (crlf_header_smuggle rule untouched by the crlf_encoded_newline narrowing) PASSED")

    print("\nALL crlf_encoded_newline FALSE-POSITIVE REGRESSION TESTS PASSED")


main()
