import os
import subprocess
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.datatypes import Severity
from core.fim_risk_classifier import LIKELY_LEGITIMATE, classify_risk
from core.git_deployment import GitDeploymentTracker, find_git_root, get_head_info


def _run_git(repo_root, *args):
    subprocess.run(["git", *args], cwd=repo_root, check=True, capture_output=True, text=True)


def _make_repo():
    repo_root = tempfile.mkdtemp()
    _run_git(repo_root, "init", "-q")
    _run_git(repo_root, "config", "user.email", "rtsa-test@example.com")
    _run_git(repo_root, "config", "user.name", "RTSA Test")
    with open(os.path.join(repo_root, "README.md"), "w") as f:
        f.write("initial\n")
    _run_git(repo_root, "add", "README.md")
    _run_git(repo_root, "commit", "-q", "-m", "initial commit")
    return repo_root


def main() -> None:
    repo_root = _make_repo()

    subdir = os.path.join(repo_root, "public")
    os.makedirs(subdir, exist_ok=True)
    assert find_git_root(subdir) == repo_root, "find_git_root must walk up from a project subdirectory"
    print("Scenario 1 (find_git_root locates the repo root from a nested project subdirectory) PASSED")

    non_git_dir = tempfile.mkdtemp()
    assert find_git_root(non_git_dir) is None
    assert get_head_info(non_git_dir) is None
    print("Scenario 2 (a plain non-git directory: no git context, never fabricated) PASSED")

    deployed_php = os.path.join(repo_root, "public", "checkout.php")
    with open(deployed_php, "w") as f:
        f.write("<?php echo 'checkout'; ?>\n")
    _run_git(repo_root, "add", "public/checkout.php")
    _run_git(repo_root, "commit", "-q", "-m", "deploy: add checkout page")

    tracker = GitDeploymentTracker(commit_recent_window_seconds=120.0)
    ctx = tracker.context_for(repo_root, deployed_php)
    assert ctx is not None
    assert ctx.commit_recent is True, "a commit made moments ago must be classified as recent"
    assert ctx.file_in_commit is True, "the file that was actually committed must match"
    assert ctx.branch, ctx.branch
    print("Scenario 3 (file just committed via git: commit_recent=True, file_in_commit=True) PASSED")

    outside_php = os.path.join(repo_root, "public", "shell.php")
    with open(outside_php, "w") as f:
        f.write("<?php system($_GET['c']); ?>\n")
    ctx_outside = tracker.context_for(repo_root, outside_php)
    assert ctx_outside is not None
    assert ctx_outside.commit_recent is True
    assert ctx_outside.file_in_commit is False, (
        "a file that appeared alongside a deployment but was NOT part of the commit must never be "
        "reported as matching -- this is exactly the case that must still alert"
    )
    print("Scenario 4 (file NOT part of the deployed commit: file_in_commit=False, commit_recent still True) PASSED")

    old_ctx = tracker.context_for(repo_root, deployed_php, now=time.time() + 99999)
    assert old_ctx.commit_recent is False, "far in the future relative to the commit, it must no longer read as recent"
    assert old_ctx.file_in_commit is None, "when the commit is not recent, file membership must not be evaluated"
    print("Scenario 5 (commit no longer recent: commit_recent=False, file_in_commit=None, no stale correlation) PASSED")

    cache_key = (repo_root, tracker.context_for(repo_root, deployed_php).commit)
    assert cache_key in tracker._commit_timestamp_cache, "commit timestamp lookups must be cached, not re-shelled per file"
    print("Scenario 6 (commit timestamp/changed-files lookups are cached per repo+commit, not per file) PASSED")

    result_match = classify_risk(
        deployed_php, "created", repo_root, False,
        git_commit_match=True, git_deployment_recent=True,
    )
    assert result_match.severity == Severity.LOW, result_match.severity
    assert result_match.assessment == LIKELY_LEGITIMATE, result_match.assessment
    print("Scenario 7 (classify_risk: PHP file confirmed part of the deployed commit -> LOW/LIKELY_LEGITIMATE) PASSED")

    result_outside = classify_risk(
        outside_php, "created", repo_root, False,
        git_commit_match=False, git_deployment_recent=True,
    )
    assert result_outside.severity == Severity.HIGH, result_outside.severity
    assert "TIDAK termasuk" in result_outside.reason, result_outside.reason
    assert result_outside.confidence > 0.6, (
        f"a new PHP file appearing outside a just-deployed commit must be treated with HIGHER "
        f"confidence than a routine new-file signal, never suppressed: {result_outside.confidence}"
    )
    print("Scenario 8 (classify_risk: PHP appearing outside the deployed commit -> still HIGH, flagged explicitly) PASSED")

    upload_php = os.path.join(repo_root, "uploads", "avatar.php")
    result_upload = classify_risk(
        upload_php, "created", repo_root, False,
        git_commit_match=True, git_deployment_recent=True,
    )
    assert result_upload.severity == Severity.CRITICAL, (
        f"a PHP file inside an uploads/ directory must stay CRITICAL regardless of git commit "
        f"match -- git trust must never become a global whitelist: {result_upload.severity}"
    )
    print("Scenario 9 (PHP inside uploads/ stays CRITICAL even with a matching git commit -- no blanket trust) PASSED")

    result_no_git = classify_risk("/home/other/htdocs/site/index.php", "modified", None, False)
    assert result_no_git.severity == Severity.MEDIUM, (
        f"with no project_root/git context at all, existing non-git behavior must be unchanged: {result_no_git.severity}"
    )
    print("Scenario 10 (no git context available: falls back to existing non-git classification, unchanged) PASSED")

    deployed_index = os.path.join(repo_root, "public", "index.html")
    with open(deployed_index, "w") as f:
        f.write("<html>v2</html>\n")
    _run_git(repo_root, "add", "public/index.html")
    _run_git(repo_root, "commit", "-q", "-m", "deploy: update homepage")
    tracker2 = GitDeploymentTracker(commit_recent_window_seconds=120.0)
    index_ctx = tracker2.context_for(repo_root, deployed_index)
    result_index_match = classify_risk(
        deployed_index, "modified", repo_root, False,
        git_commit_match=index_ctx.file_in_commit, git_deployment_recent=index_ctx.commit_recent,
    )
    assert index_ctx.file_in_commit is True
    assert result_index_match.severity == Severity.LOW, result_index_match.severity
    assert result_index_match.assessment == LIKELY_LEGITIMATE
    print("Scenario 11 (index.html change verified as part of a deployed git commit -> LOW/LIKELY_LEGITIMATE) PASSED")

    defaced_index = os.path.join(repo_root, "public", "index.html")
    result_index_outside = classify_risk(
        defaced_index, "modified", repo_root, False,
        git_commit_match=False, git_deployment_recent=True,
    )
    assert result_index_outside.severity == Severity.CRITICAL, result_index_outside.severity
    assert "TIDAK termasuk" in result_index_outside.reason
    assert result_index_outside.confidence > 0.55
    print("Scenario 12 (index.html changed outside a just-deployed commit -> CRITICAL, explicit warning) PASSED")

    result_index_no_signal = classify_risk(
        "/home/site/htdocs/site/index.html", "modified", None, False,
    )
    assert result_index_no_signal.severity == Severity.CRITICAL, (
        f"with zero deployment/git signal, index.html changes must stay maximally alerting, "
        f"unchanged from prior behavior: {result_index_no_signal.severity}"
    )
    print("Scenario 13 (index.html change with no deployment/git context at all: stays CRITICAL, no blind downgrade) PASSED")

    print("\nALL GIT DEPLOYMENT CORRELATION TESTS PASSED")


main()
