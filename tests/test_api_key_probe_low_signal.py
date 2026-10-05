import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.injection_signatures import classify_request
from modules.nginx_monitor import _WEB_ATTACK_SIGNATURES

CREDENTIAL_PROBE_PATHS = [
    "/api/data?apikey=undefined",
    "/api/data?api_key=undefined",
    "/api/data?token=undefined",
    "/api/data?secret=null",
    "/api/data?key=test123",
    "/api/user/profile?apikey=undefined&token=null",
    "/v1/status?apikey=",
    "/graphql?secret=undefined&api_key=undefined",
]


def main() -> None:
    for path in CREDENTIAL_PROBE_PATHS:
        static_matches = [
            category.value for category, pattern, _confidence in _WEB_ATTACK_SIGNATURES
            if pattern.search(path)
        ]
        assert not static_matches, (
            f"a credential-parameter-name-only probe must never match a static web-attack "
            f"signature on the parameter NAME alone (sections 22/57): {path} matched {static_matches}"
        )

        result = classify_request("GET", path, user_agent="Mozilla/5.0")
        assert result.top_category is None, (
            f"classify_request must never flag a credential-parameter-name-only probe with no "
            f"actual attack payload as a security signal: {path} -> {result.top_category}"
        )
    print(
        f"Scenario 1 ({len(CREDENTIAL_PROBE_PATHS)} apikey/api_key/token/secret/key-shaped probes "
        f"never match any signature -- LOW_SIGNAL_PROBE policy already satisfied structurally, "
        f"security_score effectively 0, outbound effectively false) PASSED"
    )

    real_attack_with_credential_param = "/api/data?apikey=undefined&id=1 UNION SELECT username,password FROM users--"
    result = classify_request("GET", real_attack_with_credential_param, user_agent="sqlmap/1.7")
    static_matches = [
        category.value for category, pattern, _confidence in _WEB_ATTACK_SIGNATURES
        if pattern.search(real_attack_with_credential_param)
    ]
    assert static_matches or result.top_category is not None, (
        "a genuine attack payload riding alongside an unrelated credential-shaped parameter "
        "must still be detected in full -- the credential-parameter exemption must never "
        "suppress a real, independently-detected attack signature"
    )
    print("Scenario 2 (a real attack payload alongside a credential-shaped param is still detected) PASSED")


main()
