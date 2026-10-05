import calendar
import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import (
    DiscordConfig, SSHEventTimingConfig, SSHMonitorConfig, SSHNotificationsConfig, SSHSessionConfig,
)
from core.datatypes import EventCategory
from core.event_bus import EventBus
from core.pipeline_metrics import get_ssh_metrics
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.ssh_monitor import SSHMonitor

FP = "SHA256:knownkeyfingerprint"
SSH_PORT = 23109
USER = "newusproud"
IP = "182.10.36.39"
LOGIN_AT = float(calendar.timegm((2026, 10, 1, 3, 15, 22)))
LOGOUT_AT = LOGIN_AT + 12 * 60 + 34
CLOSED = "pam_unix(sshd:session): session closed for user {user}"
ACCEPTED = "Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 {fp}"
ACCEPTED_PASSWORD = "Accepted password for {user} from {ip} port {port} ssh2"
FAILED = "Failed password for invalid user {user} from {ip} port {port} ssh2"
DISCONNECTED = "Disconnected from user {user} {ip} port {port}"
RECEIVED_DISCONNECT = "Received disconnect from {ip} port {port}:11: disconnected by user"

REALISTIC_TIMING = SSHEventTimingConfig(
    realtime_max_delay_seconds=10.0, delayed_max_delay_seconds=60.0, stale_after_seconds=300.0,
    replay_grace_seconds=30.0,
)
WIDE_TIMING = SSHEventTimingConfig(
    realtime_max_delay_seconds=1e9, delayed_max_delay_seconds=1e9, stale_after_seconds=1e9,
)


def known_meta(fingerprint, **over):
    meta = {
        "hostname": "srv", "server_name": "Server2", "ssh_service": "sshd", "ssh_port": SSH_PORT,
        "trusted_linux_user": True, "fingerprint": fingerprint, "key_type": "ED25519",
        "identity_status": "DISCOVERED", "key_owner": "owner@example.com", "key_owner_basis": "REGISTRY",
        "key_user_mismatch": False, "key_source": "/home/newusproud/.ssh/authorized_keys",
    }
    meta.update(over)
    return meta


def unknown_key_meta(fingerprint, **over):
    meta = {
        "hostname": "srv", "server_name": "Server2", "ssh_service": "sshd", "ssh_port": SSH_PORT,
        "trusted_linux_user": True, "fingerprint": fingerprint, "key_type": "ED25519",
        "identity_status": "UNKNOWN_KEY", "key_owner": "UNKNOWN", "key_owner_basis": "UNKNOWN",
        "key_user_mismatch": None,
    }
    meta.update(over)
    return meta


def make_monitor(state_path="", timing=WIDE_TIMING, logout_policy="STORE", known_login_policy="", meta_factory=None,
                 trusted=("newusproud",), sessions=None, ssh_port=SSH_PORT):
    cfg = SSHMonitorConfig(
        enabled=True, geoip_lookup=False, state_path=state_path, trusted_linux_users=list(trusted), use_sshd_t=False,
        event_timing=timing,
        notifications=SSHNotificationsConfig(known_login_policy=known_login_policy, logout_policy=logout_policy),
        sessions=sessions or SSHSessionConfig(reconnect_window_seconds=300.0, activity_quiet_seconds=60.0),
    )
    mon = SSHMonitor(EventBus(), cfg)
    mon._ssh_dest_port, mon._ssh_dest_ports, mon._ssh_dest_port_source = ssh_port, {ssh_port}, "sshd_config"
    published = []
    mon.publish = lambda ev: published.append(ev)
    factory = meta_factory or known_meta

    def meta_for(sport, keytype, fingerprint, severity, user, ip=None):
        extra = {} if fingerprint else {"identity_status": "NOT_REGISTERED", "key_user_mismatch": None}
        return {**mon._base_metadata(sport), **factory(fingerprint, **extra)}

    mon._success_metadata = meta_for
    return mon, published


def accepted(user=USER, ip=IP, port=21509, fp=FP):
    return ACCEPTED.format(user=user, ip=ip, port=port, fp=fp)


def closed(user=USER):
    return CLOSED.format(user=user)


def by_cat(published, category):
    return [e for e in published if e.category == category]


def logouts(published):
    return by_cat(published, EventCategory.SSH_LOGOUT)


def fields_of(event, dispatcher=None):
    dispatcher = dispatcher or DiscordWebhookDispatcher(EventBus(), DiscordConfig(alert_channel_id=1))
    return {f["name"]: f["value"] for f in dispatcher._build_payload(event)["embeds"][0]["fields"]}


async def deliver(events):
    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig(alert_channel_id=1))
    sent = []

    class Bot:
        def is_ready(self):
            return True

    async def send(payload, **kwargs):
        sent.append(payload)
        return ("OK", 1, len(sent))

    dispatcher._bot, dispatcher._send_via_bot = Bot(), send
    for event in events:
        await dispatcher._on_event(event)
    return sent


def counters():
    return get_ssh_metrics().snapshot()["counters"]


def reset_metrics():
    get_ssh_metrics().reset()


def now():
    return time.time()


class FrozenClock:
    def __init__(self, start):
        self.t = float(start)
        self._orig = None

    def __enter__(self):
        self._orig = time.time
        time.time = lambda: self.t
        return self

    def __exit__(self, *exc):
        time.time = self._orig
        return False

    def at(self, value):
        self.t = float(value)
