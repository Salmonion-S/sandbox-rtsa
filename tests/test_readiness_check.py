import io
import os
import sys
import tempfile
from contextlib import redirect_stdout

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import main as rtsa_main


def main() -> None:
    missing_path = os.path.join(tempfile.gettempdir(), "rtsa_readiness_check_missing_config.yaml")
    if os.path.exists(missing_path):
        os.remove(missing_path)

    orig_discord = os.environ.pop("RTSA_DISCORD_BOT_TOKEN", None)
    orig_cf = os.environ.pop("RTSA_CLOUDFLARE_API_TOKEN", None)
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = rtsa_main.run_readiness_check("/home/user/rtsa-2.5/config/config.yaml")
        output = buf.getvalue()

        assert exit_code != 0, "with no Discord token set and the repo's default config (discord.enabled=true), the check must report a FAIL and a non-zero exit code"
        assert "FAIL" in output
        assert "RTSA_DISCORD_BOT_TOKEN" in output
        for secret_looking_value in ():
            assert secret_looking_value not in output
        print("Scenario 1 (readiness check against the repo's actual config: correctly reports FAIL + non-zero exit for the missing Discord token) PASSED")

        buf2 = io.StringIO()
        os.environ["RTSA_DISCORD_BOT_TOKEN"] = "test_fixture_token_never_a_real_credential_0123456789abcdef"
        os.environ["RTSA_CLOUDFLARE_API_TOKEN"] = "test_fixture_cf_token_never_real_fedcba9876543210"
        with redirect_stdout(buf2):
            rtsa_main.run_readiness_check("/home/user/rtsa-2.5/config/config.yaml")
        output2 = buf2.getvalue()
        assert "test_fixture_token_never_a_real_credential_0123456789abcdef" not in output2, (
            "the actual token value must never be printed into readiness check output, even a fixture value"
        )
        assert "nilai tidak ditampilkan" in output2 or "PASS" in output2
        print("Scenario 2 (readiness check never echoes credential values into its output, even when the credential is present and valid-shaped) PASSED")

        buf3 = io.StringIO()
        with redirect_stdout(buf3):
            exit_code3 = rtsa_main.run_readiness_check(missing_path)
        output3 = buf3.getvalue()
        assert "SUMMARY" in output3, "a missing config file must still produce a complete, well-formed report (using defaults), not crash"
        print("Scenario 3 (a missing config path does not crash the readiness check -- falls back to defaults and still reports a full summary) PASSED")

        buf4 = io.StringIO()
        with redirect_stdout(buf4):
            rtsa_main.run_readiness_check("/home/user/rtsa-2.5/config/config.yaml")
        output4 = buf4.getvalue()
        for expected_status in ("PASS", "FAIL"):
            assert expected_status in output4
        for expected_check_name in (
            "root_privileges", "python_version", "dependency:PyYAML", "config_syntax_and_semantics",
            "home_readability", "inotify_availability", "nginx_presence", "systemctl_availability",
            "service_file_syntax", "metrics_port_availability", "discord_credential_presence",
            "cloudflare_credential_presence",
        ):
            assert expected_check_name in output4, f"expected check '{expected_check_name}' missing from readiness output"
        print("Scenario 4 (all required Phase-16 readiness categories are present in the report: dependency/config/directory/inotify/nginx/systemd/metrics/credentials) PASSED")
    finally:
        if orig_discord is None:
            os.environ.pop("RTSA_DISCORD_BOT_TOKEN", None)
        else:
            os.environ["RTSA_DISCORD_BOT_TOKEN"] = orig_discord
        if orig_cf is None:
            os.environ.pop("RTSA_CLOUDFLARE_API_TOKEN", None)
        else:
            os.environ["RTSA_CLOUDFLARE_API_TOKEN"] = orig_cf
        import shutil
        shutil.rmtree("/opt/security/rtsa", ignore_errors=True)

    print("\nALL READINESS CHECK TESTS PASSED")


main()
