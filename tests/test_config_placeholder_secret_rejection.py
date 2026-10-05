import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from config.manager import (
    CloudflareConfig, ConfigManager, ConfigValidationError, DiscordConfig, ModulesConfig,
    NginxMonitorConfig, RTSAConfig, SvgUploadScannerConfig, looks_like_placeholder_secret,
)


def _validate(cfg: RTSAConfig) -> None:
    ConfigManager._validate_semantics(cfg)


def main() -> None:
    assert looks_like_placeholder_secret("REPLACE_WITH_ROTATED_DISCORD_BOT_TOKEN")
    assert looks_like_placeholder_secret("REPLACE_WITH_ROTATED_CLOUDFLARE_API_TOKEN")
    assert looks_like_placeholder_secret("<your-token-here>")
    assert looks_like_placeholder_secret("CHANGEME")
    assert looks_like_placeholder_secret("your_api_key_goes_here")
    assert not looks_like_placeholder_secret("MTA1NzQ5MjM4NDc2NDI5NTY4.GxYzAb.cdefghijklmnopqrstuvwxyz0123456")
    assert not looks_like_placeholder_secret("")
    print("Scenario 1 (placeholder-shaped secret values are detected by pattern, real-looking tokens are not) PASSED")

    env_var = "RTSA_TEST_DISCORD_TOKEN_PLACEHOLDER"
    orig = os.environ.pop(env_var, None)
    try:
        os.environ[env_var] = "REPLACE_WITH_ROTATED_DISCORD_BOT_TOKEN"
        cfg = RTSAConfig(discord=DiscordConfig(enabled=True, bot_token_env_var=env_var))
        try:
            _validate(cfg)
            raised = False
        except ConfigValidationError as exc:
            raised = True
            message = str(exc)
        assert raised, "a Discord bot token env var still containing the deploy/rtsa.env placeholder must fail validation"
        assert "REPLACE_WITH_ROTATED_DISCORD_BOT_TOKEN" not in message, (
            f"the actual (even placeholder) secret value must never be echoed into the validation "
            f"error message: {message!r}"
        )
        assert env_var in message, "the error must name which env var is affected, without the value"
        print("Scenario 2 (Discord bot token left as the deploy/rtsa.env placeholder fails config validation, value never echoed) PASSED")
    finally:
        if orig is None:
            os.environ.pop(env_var, None)
        else:
            os.environ[env_var] = orig

    cf_env_var = "RTSA_TEST_CLOUDFLARE_TOKEN_PLACEHOLDER"
    orig_cf = os.environ.pop(cf_env_var, None)
    try:
        os.environ[cf_env_var] = "REPLACE_WITH_ROTATED_CLOUDFLARE_API_TOKEN"
        cfg = RTSAConfig(
            discord=DiscordConfig(enabled=False),
            cloudflare=CloudflareConfig(enabled=True, api_token_env_var=cf_env_var),
        )
        try:
            _validate(cfg)
            raised = False
        except ConfigValidationError:
            raised = True
        assert raised, "a Cloudflare API token env var still containing the deploy/rtsa.env placeholder must fail validation"
        print("Scenario 3 (Cloudflare API token left as the deploy/rtsa.env placeholder fails config validation) PASSED")
    finally:
        if orig_cf is None:
            os.environ.pop(cf_env_var, None)
        else:
            os.environ[cf_env_var] = orig_cf

    real_env_var = "RTSA_TEST_DISCORD_TOKEN_REAL"
    orig_real = os.environ.pop(real_env_var, None)
    try:
        os.environ[real_env_var] = "MTA1NzQ5MjM4NDc2NDI5NTY4.GxYzAb.cdefghijklmnopqrstuvwxyz0123456"
        cfg = RTSAConfig(
            discord=DiscordConfig(enabled=True, bot_token_env_var=real_env_var),
            modules=ModulesConfig(
                nginx_monitor=NginxMonitorConfig(
                    svg_upload_scanner=SvgUploadScannerConfig(enabled=False),
                ),
            ),
        )
        _validate(cfg)
        print("Scenario 4 (a real-looking token value passes validation without being flagged as a placeholder) PASSED")
    finally:
        if orig_real is None:
            os.environ.pop(real_env_var, None)
        else:
            os.environ[real_env_var] = orig_real

    missing_env_var = "RTSA_TEST_DISCORD_TOKEN_MISSING_DOES_NOT_EXIST"
    os.environ.pop(missing_env_var, None)
    cfg = RTSAConfig(discord=DiscordConfig(enabled=True, bot_token_env_var=missing_env_var))
    try:
        _validate(cfg)
        raised = False
    except ConfigValidationError:
        raised = True
    assert raised, "a completely unset token env var must still fail validation (pre-existing behavior, unchanged)"
    print("Scenario 5 (a completely unset token env var still fails validation -- pre-existing behavior preserved) PASSED")

    print("\nALL CONFIG PLACEHOLDER-SECRET REJECTION TESTS PASSED")


main()
