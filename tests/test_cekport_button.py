import asyncio
import json
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from unittest import mock

import discord

from config.manager import CloudflareConfig, DiscordConfig, ResponseEngineConfig, RTSAConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.bot import RTSABot
from discord_integration.webhook import DiscordWebhookDispatcher

_ADMIN_ROLE_ID = 555
_CRITICAL_ROLE_ID = 777

CEKPORT_LABEL = "🔎 Cek Port"

class FakeDbWorker:
    def __init__(self):
        self.incident_creates = []

    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **kwargs): self.incident_creates.append(kwargs)
    def enqueue_incident_update(self, *a, **k): pass

class FakeRole:
    def __init__(self, role_id): self.id = role_id

class FakeResponse:
    def __init__(self):
        self.messages = []
        self.deferred = False

    async def send_message(self, content=None, ephemeral=False, view=None, embed=None):
        self.messages.append(content)

    async def defer(self, ephemeral=False):
        self.deferred = True

class FakeFollowup:
    def __init__(self): self.sent = []
    async def send(self, *a, **kw): self.sent.append((a, kw))

class FakeInteraction:
    def __init__(self, member, custom_id):
        self.type = discord.InteractionType.component
        self.data = {"custom_id": custom_id}
        self.user = member
        self.response = FakeResponse()
        self.followup = FakeFollowup()
        self.message = None

    async def edit_original_response(self, **kwargs): pass

def make_member(role_ids, member_id=111, name="tester#0001"):
    member = mock.Mock(spec=discord.Member)
    member.roles = [FakeRole(r) for r in role_ids]
    member.id = member_id
    member.__str__ = mock.Mock(return_value=name)
    return member

def make_bot(detection_only=False):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=detection_only),
        cloudflare=CloudflareConfig(enabled=False),
    )
    disc_cfg = DiscordConfig(
        enabled=True, admin_role_ids=[_ADMIN_ROLE_ID], critical_command_role_ids=[_CRITICAL_ROLE_ID],
    )
    return RTSABot(disc_cfg, cfg, EventBus(), db_worker=FakeDbWorker(), supervisor=None)

def make_port_event(**overrides):
    metadata = {
        "port": 4444, "pid": 9999, "pid_create_time": 12345.0, "linux_user": "root",
        "related_process": "nc", "binary_path": "/usr/bin/nc",
    }
    metadata.update(overrides)
    return BaseEvent(
        source_module="host_persistence_detector", category=EventCategory.PERSISTENCE_NEW_PORT,
        severity=Severity.HIGH, message="Listening port baru terdeteksi: 4444 (proses: nc)",
        metadata=metadata,
    )

def all_buttons(payload):
    return [c for row in payload.get("components", []) for c in row["components"]]

def stub_incident(bot, correlation):
    payload = correlation if isinstance(correlation, (str, type(None))) else json.dumps(correlation)

    async def fake(event_id):
        return {"event_id": event_id, "correlation_data": payload}

    bot._get_incident_full = fake

async def main():
    disc_cfg = DiscordConfig(enabled=True)
    event = make_port_event()

    webhook = DiscordWebhookDispatcher(EventBus(), disc_cfg, detection_only=False, firewall_backend="iptables")
    payload = webhook._build_payload(event)
    buttons = all_buttons(payload)
    btn = next((b for b in buttons if b["label"] == CEKPORT_LABEL), None)
    assert btn is not None, [b["label"] for b in buttons]
    assert btn["custom_id"] == f"rtsa_action:cekport:{event.event_id}", btn
    print("Scenario 1 (PERSISTENCE_NEW_PORT payload carries the Cek Port button with the right custom_id) PASSED")

    webhook_do = DiscordWebhookDispatcher(EventBus(), disc_cfg, detection_only=True, firewall_backend="iptables")
    labels_do = {b["label"] for b in all_buttons(webhook_do._build_payload(event))}
    assert labels_do == {CEKPORT_LABEL, "📜 Riwayat", "🕐 Linimasa", "🙈 Abaikan"}, labels_do
    print("Scenario 2 (detection_only=True -- Cek Port still rendered, every mutating button still omitted) PASSED")

    for backend in ("iptables", "none"):
        for extra in ({}, {"systemd_unit": "evil.service"}, {"pm2_app_name": "evilapp"},
                      {"docker_container_id": "abc123def456"}):
            wh = DiscordWebhookDispatcher(EventBus(), disc_cfg, detection_only=False, firewall_backend=backend)
            rows = wh._build_payload(make_port_event(**extra)).get("components", [])
            assert len(rows) <= 5, f"too many action rows for {backend}/{extra}: {len(rows)}"
            for row in rows:
                assert len(row["components"]) <= 5, (
                    f"row over Discord's 5-button cap for {backend}/{extra}: "
                    f"{[c['label'] for c in row['components']]}"
                )
    print("Scenario 3 (all port-alert layouts stay within Discord's 5-buttons-per-row limit) PASSED")

    lsof_header = "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME"

    def lsof_listening_output():
        return "\n".join([lsof_header, "nc 9999 root 3u IPv4 1 0t0 TCP *:4444 (LISTEN)"])

    bot = make_bot()
    stub_incident(bot, {"port": 4444, "pid": 9999})
    member = make_member([_CRITICAL_ROLE_ID])
    interaction = FakeInteraction(member, f"rtsa_action:cekport:{event.event_id}")
    probed = []

    async def fake_run_root_command(argv, timeout):
        probed.append(argv)
        return 0, lsof_listening_output(), ""

    bot._run_root_command = fake_run_root_command
    await bot.on_interaction(interaction)

    assert probed, "the handler never actually ran lsof against the live port"
    assert interaction.response.deferred, "a port scan can take a moment; the reply must be deferred first"
    assert len(interaction.followup.sent) == 1, interaction.followup.sent
    embed = interaction.followup.sent[0][1]["embed"]
    field_values = {f.name: f.value for f in embed.fields}
    assert field_values["Port"] == "4444" and field_values["Status"] == "LISTENING", field_values
    assert field_values["Process"] == "nc", field_values
    assert field_values["PID"] == "9999", field_values
    assert interaction.followup.sent[0][1]["ephemeral"] is True, "port state is operator-only, keep it ephemeral"
    print("Scenario 4 (button re-checks the incident's own port and reports the live listening state) PASSED")

    bot._run_root_command = fake_run_root_command
    direct = await bot._cekport_embed(4444)
    assert direct.to_dict() == embed.to_dict(), (
        "the button and the /cekport command produced different embeds for the same host state"
    )
    print("Scenario 5 (button output is byte-identical to the /cekport command for the same host state) PASSED")

    async def fake_run_root_command_empty(argv, timeout):
        return 1, "", ""

    bot6 = make_bot()
    bot6._run_root_command = fake_run_root_command_empty
    stub_incident(bot6, {"port": 4444})
    interaction6 = FakeInteraction(make_member([_CRITICAL_ROLE_ID]), f"rtsa_action:cekport:{event.event_id}")
    await bot6.on_interaction(interaction6)
    embed6 = interaction6.followup.sent[0][1]["embed"]
    field_values6 = {f.name: f.value for f in embed6.fields}
    assert field_values6["Status"] == "NOT LISTENING", field_values6
    assert "4444" in embed6.description, embed6.description
    print("Scenario 6 (port no longer listening -- clean 'NOT LISTENING' answer, the false-positive verdict) PASSED")

    for label, corr in (
        ("no correlation_data at all", None),
        ("correlation_data is not valid JSON", "{not json"),
        ("correlation_data has no port key", {"pid": 9999}),
        ("correlation_data has a null port", {"port": None}),
        ("port stored as a non-numeric string", {"port": "not-a-port"}),
        ("port stored as a list", {"port": [4444]}),
    ):
        b = make_bot()
        stub_incident(b, corr)

        async def must_not_run(argv, timeout, label=label):
            raise AssertionError(f"{label}: unresolvable port must never reach lsof")

        b._run_root_command = must_not_run
        i = FakeInteraction(make_member([_CRITICAL_ROLE_ID]), f"rtsa_action:cekport:{event.event_id}")
        await b.on_interaction(i)
        assert i.response.messages and "Tidak ada info port tersimpan" in i.response.messages[0], (label, i.response.messages)
        assert not i.followup.sent, f"{label}: must not send a port report it could not build"
    print("Scenario 7 (missing/corrupt/portless correlation data -- clean error on 6 shapes, no crash) PASSED")

    bot7b = make_bot()
    bot7b._run_root_command = fake_run_root_command
    stub_incident(bot7b, {"port": "4444"})
    i7b = FakeInteraction(make_member([_CRITICAL_ROLE_ID]), f"rtsa_action:cekport:{event.event_id}")
    await bot7b.on_interaction(i7b)
    assert i7b.followup.sent, i7b.response.messages
    field_values7b = {f.name: f.value for f in i7b.followup.sent[0][1]["embed"].fields}
    assert field_values7b["Status"] == "LISTENING", field_values7b
    print("Scenario 7b (port stored as a numeric string is still checked, not rejected) PASSED")

    bot8 = make_bot()

    async def no_incident(event_id): return None

    bot8._get_incident_full = no_incident
    i8 = FakeInteraction(make_member([_CRITICAL_ROLE_ID]), f"rtsa_action:cekport:{event.event_id}")
    await bot8.on_interaction(i8)
    assert i8.response.messages and "Tidak ada info port tersimpan" in i8.response.messages[0], i8.response.messages
    print("Scenario 8 (incident no longer in the DB -- clean refusal, no attribute error on a None record) PASSED")

    bot9 = make_bot()
    stub_incident(bot9, {"port": 4444})
    i9 = FakeInteraction(make_member([]), f"rtsa_action:cekport:{event.event_id}")

    async def must_not_run9(argv, timeout):
        raise AssertionError("unauthorized click reached the port scan")

    bot9._run_root_command = must_not_run9
    await bot9.on_interaction(i9)
    assert "tidak memiliki izin" in (i9.response.messages[0] or "").lower(), i9.response.messages
    assert not i9.followup.sent
    print("Scenario 9 (unauthorized member rejected before the port is ever inspected) PASSED")

    bot10 = make_bot(detection_only=True)
    bot10._run_root_command = fake_run_root_command
    stub_incident(bot10, {"port": 4444})
    i10 = FakeInteraction(make_member([_CRITICAL_ROLE_ID]), f"rtsa_action:cekport:{event.event_id}")
    await bot10.on_interaction(i10)
    assert i10.followup.sent, "detection_only must not block a read-only port check"
    field_values10 = {f.name: f.value for f in i10.followup.sent[0][1]["embed"].fields}
    assert field_values10["Status"] == "LISTENING", field_values10
    print("Scenario 10 (detection_only=True -- the read-only check still runs and answers) PASSED")

    bot11 = make_bot()

    async def boom(argv, timeout):
        raise OSError("permission denied reading /proc/net/tcp")

    bot11._run_root_command = boom
    embed11 = await bot11._cekport_embed(4444)
    field_values11 = {f.name: f.value for f in embed11.fields}
    assert field_values11["Status"] == "ERROR", field_values11
    assert field_values11["Status"] != "NOT LISTENING", "a failed probe must never be reported as 'not listening'"
    print("Scenario 11 (socket enumeration failure -- reported as a failure, never as an all-clear) PASSED")

    print("\nALL /cekport BUTTON TESTS PASSED")

asyncio.run(asyncio.wait_for(main(), timeout=120))
