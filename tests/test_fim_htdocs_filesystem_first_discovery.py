import os
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from core.fs_discovery import discover_home_root_projects, discover_htdocs_projects


def main() -> None:
    d = tempfile.mkdtemp()

    markerless = os.path.join(d, "phpuser", "htdocs", "markerless-project.id")
    os.makedirs(markerless)
    with open(os.path.join(markerless, "shell.php"), "w") as f:
        f.write("<?php echo 1; ?>")

    empty_project = os.path.join(d, "phpuser", "htdocs", "empty-project.id")
    os.makedirs(empty_project)

    domain_a = os.path.join(d, "multiuser", "htdocs", "site-a.id")
    domain_b = os.path.join(d, "multiuser", "htdocs", "site-b.id")
    os.makedirs(domain_a)
    os.makedirs(domain_b)

    nested = os.path.join(d, "nesteduser", "htdocs", "app.id", "subdir", "deeper")
    os.makedirs(nested)

    denied_user = os.path.join(d, "denieduser", "htdocs")
    os.makedirs(denied_user)
    os.chmod(denied_user, 0o000)

    readable_user = os.path.join(d, "denieduser2", "htdocs", "still-readable.id")
    os.makedirs(readable_user)

    outside_target = os.path.join(d, "outside-target")
    os.makedirs(outside_target)
    escape_user_htdocs = os.path.join(d, "escapeuser", "htdocs")
    os.makedirs(escape_user_htdocs)
    escape_link = os.path.join(escape_user_htdocs, "escape-project")
    try:
        os.symlink(outside_target, escape_link)
        symlink_supported = True
    except OSError:
        symlink_supported = False

    try:
        found = discover_htdocs_projects(d)

        assert markerless in found, (
            f"a markerless PHP project directory under htdocs must be discovered by filesystem "
            f"structure alone, without requiring composer.json/package.json/index.php: {found}"
        )
        print("Scenario 1 (markerless PHP project under htdocs is discovered by filesystem structure alone) PASSED")

        assert empty_project in found, (
            f"a completely empty project directory under htdocs must still be discovered -- "
            f"discovery must not depend on the project having any content yet: {found}"
        )
        print("Scenario 2 (empty project directory under htdocs is still discovered) PASSED")

        assert domain_a in found and domain_b in found, (
            f"multiple sibling domains under the same user's htdocs must all be discovered independently: {found}"
        )
        print("Scenario 3 (multiple domains under the same htdocs are all discovered) PASSED")

        nested_project_root = os.path.join(d, "nesteduser", "htdocs", "app.id")
        assert nested_project_root in found, f"the immediate htdocs child must be the project root: {found}"
        assert nested not in found, (
            f"a directory nested INSIDE a project (not itself a direct htdocs child) must not be "
            f"treated as a separate project root: {found}"
        )
        print("Scenario 4 (nested subdirectories inside a project are not treated as separate project roots) PASSED")

        if symlink_supported:
            assert escape_link not in found, (
                f"a symlink under htdocs pointing outside the home tree must never be treated as a "
                f"project root (symlink escape must be handled safely, not followed): {found}"
            )
            assert outside_target not in found
            print("Scenario 5 (a symlink escaping the home tree is not followed or treated as a project) PASSED")
        else:
            print("Scenario 5 (symlink creation unsupported in this environment -- skipped)")

        assert readable_user in found, (
            f"a permission-denied user directory must not prevent discovery from continuing for "
            f"other, readable users: {found}"
        )
        print("Scenario 6 (permission-denied directory is skipped without halting discovery of other projects) PASSED")

        found_again = discover_htdocs_projects(d)
        assert sorted(found) == sorted(found_again), "discovery must be deterministic/idempotent across repeated calls"
        assert len(found) == len(set(found)), f"no duplicate canonical paths must appear in the result: {found}"
        print("Scenario 7 (discovery is deterministic and produces no duplicate canonical paths) PASSED")

        combined = discover_home_root_projects(d, max_depth=4)
        assert markerless in combined and empty_project in combined
        print("Scenario 8 (discover_home_root_projects unions htdocs-structural discovery with the existing marker-based fallback) PASSED")

        print("\nALL FIM HTDOCS FILESYSTEM-FIRST DISCOVERY TESTS PASSED")
    finally:
        os.chmod(denied_user, 0o755)


main()
