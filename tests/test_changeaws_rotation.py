import asyncio
import os
import shutil
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from discord_integration import credential_rotation as cr

_SECRET_OLD = "oldSecretValueThatIsLongEnough12345"
_SECRET_NEW = "newSecretValueThatIsLongEnough67890"
_ACCESS_KEY_OLD = "AKIAOLDOLDOLDOLD"
_ACCESS_KEY_NEW = "AKIANEWNEWNEWNEW"
_REGION_OLD = "us-east-1"
_REGION_NEW = "ap-southeast-1"


class AwsFixture:

    def __init__(self, owner, domain, uid, gid, conf_dir):
        self.owner = owner
        self.domain = domain
        self.uid = uid
        self.gid = gid
        self.conf_dir = conf_dir
        self.home = f"/home/{owner}"
        self.project = f"{self.home}/htdocs/{domain}"

    def build(
        self, *, access_key=_ACCESS_KEY_OLD, secret=_SECRET_OLD, region=_REGION_OLD,
        extra_lines="OTHER_VAR=keep_me_untouched\n", include_keys=("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"),
    ):
        os.makedirs(self.project, exist_ok=True)
        os.makedirs(f"{self.home}/logs", exist_ok=True)
        lines = []
        if "AWS_ACCESS_KEY_ID" in include_keys:
            lines.append(f"AWS_ACCESS_KEY_ID={access_key}")
        if "AWS_SECRET_ACCESS_KEY" in include_keys:
            lines.append(f"AWS_SECRET_ACCESS_KEY={secret}")
        if "AWS_REGION" in include_keys:
            lines.append(f"AWS_REGION={region}")
        content = "\n".join(lines) + "\n" + extra_lines
        env_path = f"{self.project}/.env"
        with open(env_path, "w") as f:
            f.write(content)
        os.chown(env_path, self.uid, self.gid)
        os.chmod(env_path, 0o640)

        conf_path = os.path.join(self.conf_dir, f"{self.domain}.conf")
        with open(conf_path, "w") as f:
            f.write(f"server {{\n    server_name {self.domain};\n    access_log {self.home}/logs/access.log;\n}}\n")
        return env_path

    def env_path(self):
        return f"{self.project}/.env"

    def cleanup(self):
        shutil.rmtree(self.home, ignore_errors=True)


def _target(access_key=_ACCESS_KEY_NEW, secret=_SECRET_NEW, region=_REGION_NEW):
    return {"AWS_ACCESS_KEY_ID": access_key, "AWS_SECRET_ACCESS_KEY": secret, "AWS_REGION": region}


async def main() -> None:
    assert os.geteuid() == 0, "these tests need root to create real /home/<user> fixtures"

    conf_dir = "/tmp/rtsa_aws_rotation_conf"
    shutil.rmtree(conf_dir, ignore_errors=True)
    os.makedirs(conf_dir)

    fx1 = AwsFixture("awsuser1", "aws1.example", 590601, 590601, conf_dir)
    try:
        fx1.build()
        result = await cr.apply_aws_rotation(conf_dir, _target())
        assert result.status == cr.RESULT_SUCCESS, result.status
        assert len(result.files_updated) == 1, result.file_details
        detail = result.files_updated[0]
        assert set(detail.changed_keys) == {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"}, detail
        content = open(fx1.env_path()).read()
        assert _ACCESS_KEY_NEW in content and _SECRET_NEW in content and _REGION_NEW in content
        assert _ACCESS_KEY_OLD not in content and _SECRET_OLD not in content and _REGION_OLD not in content
        assert "OTHER_VAR=keep_me_untouched" in content, "unrelated var must survive untouched"
    finally:
        fx1.cleanup()
    print("Scenario 1 (valid access key + secret + region -> update succeeds) PASSED")

    ak, sk, rg, err = cr.validate_aws_credentials(_ACCESS_KEY_NEW, "   ", _REGION_NEW)
    assert err and "SECRET" in err.upper(), err
    print("Scenario 2 (empty secret rejected before any mutation) PASSED")

    ak, sk, rg, err = cr.validate_aws_credentials(_ACCESS_KEY_NEW, _SECRET_NEW, "")
    assert err and "REGION" in err.upper(), err
    print("Scenario 3 (empty region rejected before any mutation) PASSED")

    fx4 = AwsFixture("awsuser4", "aws4.example", 590604, 590604, conf_dir)
    try:
        fx4.build(access_key=_ACCESS_KEY_NEW, secret=_SECRET_NEW, region=_REGION_NEW)
        mtime_before = os.stat(fx4.env_path()).st_mtime_ns
        result = await cr.apply_aws_rotation(conf_dir, _target())
        assert result.status == cr.RESULT_SUCCESS, result.status
        assert len(result.files_updated) == 0, result.file_details
        assert len(result.files_unchanged) == 1, result.file_details
        assert result.files_unchanged[0].status == cr.STATUS_UNCHANGED
        assert result.backups_created == 0, "an already-matching file must never be backed up/rewritten"
        mtime_after = os.stat(fx4.env_path()).st_mtime_ns
        assert mtime_before == mtime_after, "an already-matching file must never be rewritten (idempotent)"
    finally:
        fx4.cleanup()
    print("Scenario 4 (already-matching credential -> UNCHANGED, zero mutation) PASSED")

    fx5a = AwsFixture("awsuser5a", "aws5a.example", 590605, 590605, conf_dir)
    fx5b = AwsFixture("awsuser5b", "aws5b.example", 590606, 590606, conf_dir)
    fx5c = AwsFixture("awsuser5c", "aws5c.example", 590607, 590607, conf_dir)
    try:
        fx5a.build()
        fx5b.build(access_key=_ACCESS_KEY_NEW, secret=_SECRET_NEW, region=_REGION_NEW)
        fx5c.build(include_keys=())
        result = await cr.apply_aws_rotation(conf_dir, _target())
        assert result.status == cr.RESULT_SUCCESS, result.status
        assert result.projects_eligible == 2, result
        assert len(result.files_updated) == 1, result.file_details
        assert len(result.files_unchanged) == 1, result.file_details
        assert result.files_with_aws_config == 2
    finally:
        fx5a.cleanup()
        fx5b.cleanup()
        fx5c.cleanup()
    print("Scenario 5 (many-project summary: correct eligible/updated/unchanged counts) PASSED")

    fx6a = AwsFixture("awsuser6a", "aws6a.example", 590608, 590608, conf_dir)
    fx6b = AwsFixture("awsuser6b", "aws6b.example", 590609, 590609, conf_dir)
    try:
        fx6a.build()
        fx6b.build()
        orig_replace = os.replace

        def failing_replace(src, dst, *a, **k):
            if str(dst) == fx6b.env_path():
                raise OSError(28, "No space left on device (simulated)")
            return orig_replace(src, dst, *a, **k)

        os.replace = failing_replace
        try:
            result = await cr.apply_aws_rotation(conf_dir, _target())
        finally:
            os.replace = orig_replace

        assert result.status == cr.RESULT_PARTIAL_FAILURE, result.status
        assert len(result.files_updated) == 1, result.file_details
        assert len(result.files_failed) == 1, result.file_details
        assert result.files_failed[0].project == "aws6b.example"
        content_b = open(fx6b.env_path()).read()
        assert _ACCESS_KEY_OLD in content_b and _SECRET_OLD in content_b, (
            "a failed rotation must roll back to the original content, never leave a partial write"
        )
        content_a = open(fx6a.env_path()).read()
        assert _ACCESS_KEY_NEW in content_a, "the OTHER project's successful rotation must not be affected"
    finally:
        fx6a.cleanup()
        fx6b.cleanup()
    print("Scenario 6 (partial failure: one file fails+rolls back, others succeed, status PARTIAL_FAILURE) PASSED")

    fx7 = AwsFixture("awsuser7", "aws7.example", 590610, 590610, conf_dir)
    try:
        fx7.build()
        result = await cr.apply_aws_rotation(conf_dir, _target())
        assert result.status == cr.RESULT_SUCCESS
        st = os.stat(fx7.env_path())
        assert (st.st_uid, st.st_gid) == (fx7.uid, fx7.gid), "ownership must be preserved through rotation"
        assert result.files_updated[0].ownership_status == "VERIFIED"
    finally:
        fx7.cleanup()
    print("Scenario 7 (ownership preserved through rotation) PASSED")

    fx8 = AwsFixture("awsuser8", "aws8.example", 590611, 590611, conf_dir)
    try:
        assert os.geteuid() == 0
        fx8.build()
        result = await cr.apply_aws_rotation(conf_dir, _target())
        assert result.status == cr.RESULT_SUCCESS
        detail = result.files_updated[0]
        st_main = os.stat(fx8.env_path())
        assert st_main.st_uid != 0, "the rotated .env must never end up root-owned"
        assert detail.backup_path, "a successful rotation must report its backup path"
        st_backup = os.stat(detail.backup_path)
        assert st_backup.st_uid == fx8.uid and st_backup.st_gid == fx8.gid, (
            f"the backup (created via shutil.copy2, which does NOT preserve ownership) must be "
            f"explicitly re-owned to the project user, not left root-owned: "
            f"got uid={st_backup.st_uid} gid={st_backup.st_gid}"
        )
        assert detail.backup_ownership_status == "VERIFIED"
    finally:
        fx8.cleanup()
    print("Scenario 8 (as root: final file AND backup both end up project-user-owned, never root:root) PASSED")

    fx9 = AwsFixture("awsuser9", "aws9.example", 590612, 590612, conf_dir)
    try:
        fx9.build()
        result = await cr.apply_aws_rotation(conf_dir, _target())
        detail = result.files_updated[0]
        backup_content = open(detail.backup_path).read()
        assert _SECRET_OLD in backup_content
        import dataclasses
        result_repr = repr(dataclasses.asdict(result))
        assert _SECRET_OLD not in result_repr and _SECRET_NEW not in result_repr, (
            "AwsRotationResult must never carry a raw secret value anywhere in its fields"
        )
    finally:
        fx9.cleanup()
    print("Scenario 9 (backup persists on disk for recovery, but its VALUE never appears in the report) PASSED")

    fx10 = AwsFixture("awsuser10", "aws10.example", 590613, 590613, conf_dir)
    try:
        fx10.build()
        orig_replace = os.replace

        def failing_replace(src, dst, *a, **k):
            if str(dst) == fx10.env_path():
                raise OSError(13, "Permission denied (simulated)")
            return orig_replace(src, dst, *a, **k)

        os.replace = failing_replace
        try:
            result = await cr.apply_aws_rotation(conf_dir, _target())
        finally:
            os.replace = orig_replace
        assert result.status == cr.RESULT_PARTIAL_FAILURE
        fail_reason = result.files_failed[0].fail_reason
        assert _SECRET_NEW not in fail_reason and _SECRET_OLD not in fail_reason, (
            f"a failure reason must never contain the raw secret: {fail_reason!r}"
        )
    finally:
        fx10.cleanup()
    print("Scenario 10 (error/failure reason never contains the AWS secret) PASSED")

    assert cr.mask_secret(_SECRET_NEW) == "********"
    assert _SECRET_NEW[:4] not in cr.mask_secret(_SECRET_NEW)
    assert cr.mask_secret("") == "(empty)"
    masked_key = cr.mask_aws_key(_ACCESS_KEY_NEW)
    assert _ACCESS_KEY_NEW not in masked_key and masked_key.startswith(_ACCESS_KEY_NEW[:4])
    print("Scenario 11 (mask_secret never partially reveals; mask_aws_key stays a partial identifier only) PASSED")

    fx12 = AwsFixture("awsuser12", "aws12.example", 590614, 590614, conf_dir)
    try:
        fx12.build()
        mtime_before = os.stat(fx12.env_path()).st_mtime_ns
        plan = await cr.plan_aws_rotation(conf_dir, _target())
        assert plan.status == cr.RESULT_PREVIEW
        assert plan.files_to_modify == 1
        assert plan.files_already_up_to_date == 0
        mtime_after = os.stat(fx12.env_path()).st_mtime_ns
        assert mtime_before == mtime_after, "plan_aws_rotation (preview) must never write anything"
        content = open(fx12.env_path()).read()
        assert _ACCESS_KEY_OLD in content, "preview must never mutate the file"
    finally:
        fx12.cleanup()
    print("Scenario 12 (plan_aws_rotation is read-only and matches apply's diff) PASSED")

    fx13 = AwsFixture("awsuser13", "aws13.example", 590615, 590615, conf_dir)
    try:
        fx13.build(include_keys=("AWS_ACCESS_KEY_ID",))
        result = await cr.apply_aws_rotation(conf_dir, _target())
        assert result.status == cr.RESULT_SUCCESS
        detail = result.files_updated[0]
        assert detail.changed_keys == ["AWS_ACCESS_KEY_ID"], detail
        content = open(fx13.env_path()).read()
        assert "AWS_SECRET_ACCESS_KEY" not in content and "AWS_REGION" not in content, (
            "a key the file never referenced must never be appended"
        )
    finally:
        fx13.cleanup()
    print("Scenario 13 (a key absent from the file is never appended, only present keys are updated) PASSED")

    from discord_integration.bot import RTSABot

    fx14 = AwsFixture("awsuser14", "aws14.example", 590616, 590616, conf_dir)
    try:
        fx14.build()
        plan = await cr.plan_aws_rotation(conf_dir, _target())
        preview_embed = RTSABot._build_aws_rotation_preview_embed(
            plan, masked_access_key=cr.mask_aws_key(_ACCESS_KEY_NEW),
        )
        result = await cr.apply_aws_rotation(conf_dir, _target())
        result_embed = RTSABot._build_aws_rotation_result_embed(
            result, masked_access_key=cr.mask_aws_key(_ACCESS_KEY_NEW),
        )
        for embed in (preview_embed, result_embed):
            for f in embed.fields:
                assert _SECRET_NEW not in f.value and _SECRET_OLD not in f.value, (
                    f"Discord embed field {f.name!r} must never contain the raw AWS secret: {f.value!r}"
                )
            assert _SECRET_NEW not in (embed.description or "") and _SECRET_OLD not in (embed.description or "")
        secret_fields = [f for f in result_embed.fields if f.name == "AWS Secret"]
        assert secret_fields and secret_fields[0].value == "********", secret_fields
    finally:
        fx14.cleanup()
    print("Scenario 14 (Discord preview + result embeds never contain the raw AWS secret in any field) PASSED")

    shutil.rmtree(conf_dir, ignore_errors=True)
    print("\nALL /changeaws AWS CREDENTIAL ROTATION tests PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
