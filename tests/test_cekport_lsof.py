import asyncio
import os
import shutil
import socket
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import discord_integration.bot as bot_module
from config.manager import CloudflareConfig, DiscordConfig, ResponseEngineConfig, RTSAConfig
from core.event_bus import EventBus
from discord_integration.bot import RTSABot


class FakeDbWorker:
    def enqueue_action(self, *a, **k): pass


def make_bot():
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False), cloudflare=CloudflareConfig(enabled=False),
    )
    disc_cfg = DiscordConfig(enabled=True)
    return RTSABot(disc_cfg, cfg, EventBus(), db_worker=FakeDbWorker(), supervisor=None)


LSOF_HEADER = "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME"


def lsof_row(command, pid, user, fd, ftype, device, size_off, node, name):
    return f"{command} {pid} {user} {fd} {ftype} {device} {size_off} {node} {name}"


async def main():
    valid = {"1": 1, "80": 80, "443": 443, "4001": 4001, "65535": 65535, 1: 1, 4001: 4001}
    for raw, expected in valid.items():
        assert bot_module._parse_cekport_port(raw) == expected, (raw, bot_module._parse_cekport_port(raw))
    print("Test 1 (port valid: 1, 80, 443, 4001, 65535 -- diterima) PASSED")

    rejected = [
        "abc", "4001abc", "4001;whoami", "4001 && whoami", "4001 | whoami", "4001 $(whoami)",
        "4001 `whoami`", "4001 > /tmp/test", "4001 /etc/passwd", "-i", "--help", "0", "65536",
        "", " ", None, [4001], {"port": 4001}, True, False, 3.14, "4001 5000", "\n4001", "4001\n",
    ]
    for raw in rejected:
        assert bot_module._parse_cekport_port(raw) is None, f"must reject {raw!r}"
    print(f"Test 2 ({len(rejected)} payload tidak valid/injeksi -- semua ditolak, tidak ada yang lolos) PASSED")

    assert bot_module._parse_cekport_port(0) is None
    assert bot_module._parse_cekport_port(65536) is None
    assert bot_module._parse_cekport_port(-1) is None
    print("Test 3 (batas range: 0, 65536, -1 -- ditolak) PASSED")

    single = "\n".join([
        LSOF_HEADER,
        lsof_row(r"node\x20/", "2489791", "newus-backend", "25u", "IPv6", "254750112", "0t0", "TCP", "*:4001 (LISTEN)"),
    ])
    entries = bot_module._parse_lsof_i_output(single)
    assert len(entries) == 1
    e = entries[0]
    assert bot_module._lsof_process_display_name(e) == "node", e
    assert e.pid == "2489791" and e.user == "newus-backend" and e.protocol == "TCP"
    assert e.address == "*:4001" and e.state == "LISTEN"
    print("Test 4 (parsing baris tunggal sesuai contoh spesifikasi -- semua field benar) PASSED")

    ipv4 = "\n".join([LSOF_HEADER, lsof_row("nginx", "555", "root", "6u", "IPv4", "1", "0t0", "TCP", "0.0.0.0:443 (LISTEN)")])
    e4 = bot_module._parse_lsof_i_output(ipv4)[0]
    assert e4.address == "0.0.0.0:443" and e4.state == "LISTEN"
    print("Test 5 (parsing address IPv4 -- 0.0.0.0:443) PASSED")

    ipv6 = "\n".join([LSOF_HEADER, lsof_row("sshd", "1", "root", "3u", "IPv6", "1", "0t0", "TCP", "[::]:22 (LISTEN)")])
    e6 = bot_module._parse_lsof_i_output(ipv6)[0]
    assert e6.address == "[::]:22" and e6.state == "LISTEN"
    print("Test 6 (parsing address IPv6 -- [::]:22) PASSED")

    wildcard = "\n".join([LSOF_HEADER, lsof_row("dockerd", "9", "root", "4u", "IPv4", "1", "0t0", "TCP", "*:8080 (LISTEN)")])
    ew = bot_module._parse_lsof_i_output(wildcard)[0]
    assert ew.address == "*:8080"
    print("Test 7 (parsing wildcard address -- *:8080) PASSED")

    multi = "\n".join([
        LSOF_HEADER,
        lsof_row("node", "111", "newus-backend", "25u", "IPv6", "1", "0t0", "TCP", "*:4001 (LISTEN)"),
        lsof_row("nginx", "222", "root", "6u", "IPv4", "1", "0t0", "TCP", "127.0.0.1:4001 (LISTEN)"),
        lsof_row("python", "333", "app", "8u", "IPv4", "1", "0t0", "TCP", "127.0.0.1:4001->10.0.0.5:55321 (ESTABLISHED)"),
    ])
    entries_m = bot_module._parse_lsof_i_output(multi)
    assert len(entries_m) == 3, entries_m
    assert [e.pid for e in entries_m] == ["111", "222", "333"]
    assert entries_m[2].state == "ESTABLISHED" and "->" in entries_m[2].address
    print("Test 8 (multiple process -- semua baris terparse, tidak hanya baris pertama) PASSED")

    processes_text = bot_module._format_cekport_processes(entries_m)
    for pid in ("111", "222", "333"):
        assert pid in processes_text, processes_text
    print("Test 9 (format Processes -- semua process muncul, bukan hanya satu) PASSED")

    def mock_run(rc, stdout, stderr=""):
        async def fake(argv, timeout):
            assert argv[0].endswith("lsof")
            assert argv[1] == "-i"
            assert argv[2].startswith(":")
            return rc, stdout, stderr
        return fake

    bot = make_bot()
    bot._run_root_command = mock_run(1, "")
    embed = await bot._cekport_embed(4001)
    assert embed.title == "RTSA Port Check"
    field_map = {f.name: f.value for f in embed.fields}
    assert field_map["Status"] == "NOT LISTENING", field_map
    assert field_map["Port"] == "4001"
    assert "4001" in embed.description
    print("Test 10 (rc=1, output kosong -- Status NOT LISTENING) PASSED")

    bot = make_bot()
    bot._run_root_command = mock_run(0, single)
    embed = await bot._cekport_embed(4001)
    field_map = {f.name: f.value for f in embed.fields}
    assert field_map["Status"] == "LISTENING"
    assert field_map["Process"] == "node"
    assert field_map["PID"] == "2489791"
    assert field_map["User"] == "newus-backend"
    assert field_map["Protocol"] == "TCP"
    assert field_map["Address"] == "*:4001"
    assert field_map["State"] == "LISTEN"
    assert "Raw Output" in field_map
    print("Test 11 (single process LISTENING -- semua field sesuai spesifikasi) PASSED")

    bot = make_bot()
    bot._run_root_command = mock_run(0, multi)
    embed = await bot._cekport_embed(4001)
    field_map = {f.name: f.value for f in embed.fields}
    assert field_map["Status"] == "LISTENING"
    assert "Processes" in field_map
    for pid in ("111", "222", "333"):
        assert pid in field_map["Processes"]
    print("Test 12 (multiple process LISTENING -- field Processes berisi semua) PASSED")

    bot = make_bot()
    bot._run_root_command = mock_run(None, "", "timeout setelah 10.0 detik")
    embed = await bot._cekport_embed(4001)
    field_map = {f.name: f.value for f in embed.fields}
    assert field_map["Status"] == "TIMEOUT", field_map
    print("Test 13 (subprocess timeout -- Status TIMEOUT, tidak menggantung) PASSED")

    bot = make_bot()
    original_which = shutil.which
    shutil.which = lambda name: None if name == "lsof" else original_which(name)
    try:
        embed = await bot._cekport_embed(4001)
    finally:
        shutil.which = original_which
    field_map = {f.name: f.value for f in embed.fields}
    assert field_map["Status"] == "ERROR", field_map
    assert "lsof" in embed.description
    print("Test 14 (binary lsof tidak tersedia -- Status ERROR, tidak crash) PASSED")

    bot = make_bot()
    bot._run_root_command = mock_run(1, "", "lsof: Permission denied reading /proc/1/fd")
    embed = await bot._cekport_embed(4001)
    field_map = {f.name: f.value for f in embed.fields}
    assert field_map["Status"] == "PERMISSION_ERROR", field_map
    print("Test 15 (permission error dari stderr -- Status PERMISSION_ERROR, bukan NOT LISTENING) PASSED")

    bot = make_bot()
    bot._run_root_command = mock_run(2, "", "lsof: unexpected internal failure")
    embed = await bot._cekport_embed(4001)
    field_map = {f.name: f.value for f in embed.fields}
    assert field_map["Status"] == "ERROR", field_map
    print("Test 16 (lsof exit code tak terduga tanpa indikasi permission -- Status ERROR) PASSED")

    bot = make_bot()
    malformed = "this is not lsof output at all\nneither is this line"
    bot._run_root_command = mock_run(0, malformed)
    embed = await bot._cekport_embed(4001)
    field_map = {f.name: f.value for f in embed.fields}
    assert field_map["Status"] == "LISTENING", (
        f"output ada tapi tak terparse -- harus tetap LISTENING dengan fallback raw output, bukan NOT LISTENING: {field_map}"
    )
    assert "Raw Output" in field_map and "this is not lsof output" in field_map["Raw Output"]
    print("Test 17 (parser tidak mengenali format -- fallback raw output, tidak crash, tidak dianggap NOT LISTENING) PASSED")

    bot = make_bot()

    async def boom(argv, timeout):
        raise OSError("simulated spawn failure")
    bot._run_root_command = boom
    embed = await bot._cekport_embed(4001)
    field_map = {f.name: f.value for f in embed.fields}
    assert field_map["Status"] == "ERROR", field_map
    print("Test 18 (exception tak terduga saat menjalankan lsof -- Status ERROR, tidak crash, tidak bocor traceback) PASSED")

    bot = make_bot()
    embed = await bot._cekport_embed("4001;touch /tmp/rtsa-should-not-exist")
    assert "tidak valid" in embed.description.lower()
    print("Test 19 (_cekport_embed menolak payload injeksi sebelum subprocess dijalankan sama sekali) PASSED")

    bot = make_bot()
    embed = await bot._cekport_embed(0)
    assert "tidak valid" in embed.description.lower()
    embed = await bot._cekport_embed(65536)
    assert "tidak valid" in embed.description.lower()
    print("Test 20 (_cekport_embed menolak port 0 dan 65536 sebelum subprocess dijalankan) PASSED")

    captured_argv = []

    async def capture_exec(*args, **kwargs):
        captured_argv.append(args)
        raise OSError("stop before actually spawning")

    bot = make_bot()
    real_create = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = capture_exec
    try:
        await bot._cekport_embed(4001)
    finally:
        asyncio.create_subprocess_exec = real_create
    assert captured_argv, "lsof must be invoked via create_subprocess_exec"
    argv = captured_argv[0]
    assert argv == ("lsof", "-i", ":4001") or argv[0].endswith("lsof"), argv
    print("Test 21 (lsof dijalankan lewat create_subprocess_exec dengan argument list, bukan shell string) PASSED")

    srv_fb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_fb.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_fb.bind(("0.0.0.0", 0))
    fb_port = srv_fb.getsockname()[1]
    srv_fb.listen(1)
    try:
        assert bot_module._port_is_listening_via_proc(fb_port) is True, (
            "a genuinely bound, listening socket must be found via /proc/net/tcp[6]"
        )
        bot_fb = make_bot()
        bot_fb._run_root_command = mock_run(1, "")
        embed_fb = await bot_fb._cekport_embed(fb_port)
        field_map_fb = {f.name: f.value for f in embed_fb.fields}
        assert field_map_fb["Status"] == "LISTENING", (
            f"a port bound per the kernel must never be reported NOT LISTENING just because "
            f"lsof couldn't identify the owning process: {field_map_fb}"
        )
        assert "Catatan" in field_map_fb, field_map_fb
    finally:
        srv_fb.close()
    print("Test 22 (lsof gagal identifikasi proses tapi port sungguh listening -- fallback /proc mendeteksi LISTENING, bukan NOT LISTENING) PASSED")

    assert bot_module._port_is_listening_via_proc(fb_port) is False, (
        "the same port must read as not-listening via /proc/net/tcp[6] once the socket is closed"
    )
    bot_fb2 = make_bot()
    bot_fb2._run_root_command = mock_run(1, "")
    embed_fb2 = await bot_fb2._cekport_embed(fb_port)
    field_map_fb2 = {f.name: f.value for f in embed_fb2.fields}
    assert field_map_fb2["Status"] == "NOT LISTENING", (
        f"a genuinely closed port must still report NOT LISTENING even with the /proc fallback active: {field_map_fb2}"
    )
    print("Test 23 (port sungguh tidak listening -- fallback /proc tidak menghasilkan false positive) PASSED")

    ss_sample = 'LISTEN 0      511                *:4002             *:*    users:(("next-server (v1",pid=2531027,fd=23))'
    assert bot_module._parse_ss_listening_owner(ss_sample) == ("next-server (v1", "2531027")
    assert bot_module._parse_ss_listening_owner("") is None
    assert bot_module._parse_ss_listening_owner("garbage with no LISTEN state") is None
    print("Test 24 (parsing output ss -tlnp -- ekstrak process name & PID sesuai laporan produksi) PASSED")

    async def lsof_fails_ss_succeeds(argv, timeout):
        if argv[0].endswith("lsof"):
            return 1, "", ""
        if argv[0].endswith("ss"):
            return 0, ss_sample, ""
        raise AssertionError(f"unexpected argv: {argv}")

    bot_ss = make_bot()
    bot_ss._run_root_command = lsof_fails_ss_succeeds
    real_which = shutil.which
    shutil.which = lambda name: f"/usr/bin/{name}" if name in ("lsof", "ss") else real_which(name)
    real_proc_check = bot_module._port_is_listening_via_proc
    bot_module._port_is_listening_via_proc = lambda port: True
    try:
        embed_ss = await bot_ss._cekport_embed(4002)
    finally:
        shutil.which = real_which
        bot_module._port_is_listening_via_proc = real_proc_check
    field_map_ss = {f.name: f.value for f in embed_ss.fields}
    assert field_map_ss["Status"] == "LISTENING", field_map_ss
    assert field_map_ss["Process"] == "next-server (v1", field_map_ss
    assert field_map_ss["PID"] == "2531027", field_map_ss
    print("Test 25 (lsof gagal tapi ss berhasil identifikasi proses -- Process & PID terisi, sesuai laporan produksi persis) PASSED")

    async def lsof_fails_only(argv, timeout):
        return 1, "", ""

    bot_noss = make_bot()
    bot_noss._run_root_command = lsof_fails_only
    real_which2 = shutil.which
    shutil.which = lambda name: f"/usr/bin/{name}" if name == "lsof" else None
    real_proc_check2 = bot_module._port_is_listening_via_proc
    bot_module._port_is_listening_via_proc = lambda port: True
    try:
        embed_noss = await bot_noss._cekport_embed(4002)
    finally:
        shutil.which = real_which2
        bot_module._port_is_listening_via_proc = real_proc_check2
    field_map_noss = {f.name: f.value for f in embed_noss.fields}
    assert field_map_noss["Status"] == "LISTENING", field_map_noss
    assert "Process" not in field_map_noss, field_map_noss
    assert "Catatan" in field_map_noss, field_map_noss
    print("Test 26 (ss tidak tersedia sama sekali -- tetap LISTENING dengan catatan generik, tidak crash) PASSED")

    print("\nALL /cekport LSOF PARSING & VALIDATION TESTS PASSED (mocked layer)")

    if shutil.which("lsof") is None:
        print("\nSKIPPED: real-lsof tests -- `lsof` binary is not installed in this environment.")
        print("Unit tests above already cover parsing/validation logic; the real-subprocess")
        print("layer could not be exercised here. Run this file on a host with lsof to confirm.")
    else:
        bot = make_bot()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        real_port = srv.getsockname()[1]
        srv.listen(1)
        try:
            embed = await bot._cekport_embed(real_port)
            field_map = {f.name: f.value for f in embed.fields}
            assert field_map["Status"] == "LISTENING", field_map
            assert field_map["Port"] == str(real_port)
            assert "PID" in field_map
        finally:
            srv.close()
        print(f"Test 27 (REAL lsof -i :{real_port} terhadap socket asli -- terdeteksi LISTENING) PASSED")

        closed_port = real_port
        embed2 = await bot._cekport_embed(closed_port)
        field_map2 = {f.name: f.value for f in embed2.fields}
        assert field_map2["Status"] == "NOT LISTENING", (
            f"port {closed_port} sudah ditutup, lsof asli harus melaporkan NOT LISTENING: {field_map2}"
        )
        print(f"Test 28 (REAL lsof -i :{closed_port} setelah socket ditutup -- NOT LISTENING) PASSED")

        tmpdir = tempfile.mkdtemp()
        marker = os.path.join(tmpdir, "rtsa-injection-marker")
        payloads = [
            f"4001;touch {marker}",
            f"4001 && touch {marker}",
            f"4001 | touch {marker}",
            f"$(touch {marker})",
            f"`touch {marker}`",
        ]
        orig_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            for payload in payloads:
                assert bot_module._parse_cekport_port(payload) is None, payload
                rc, stdout, stderr = await bot._run_root_command(
                    ["lsof", "-i", f":{payload}"], timeout=bot_module._CEKPORT_TIMEOUT_SECONDS,
                )
                assert not os.path.exists(marker), (
                    f"COMMAND INJECTION: payload {payload!r} created {marker} -- create_subprocess_exec "
                    f"must never allow this"
                )
        finally:
            os.chdir(orig_cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)
        print(f"Test 29 (REAL subprocess: {len(payloads)} payload injeksi -- {marker!r} TIDAK PERNAH terbuat) PASSED")

        spawned_pids = []
        real_create_exec = asyncio.create_subprocess_exec

        async def tracking_create_exec(*args, **kwargs):
            proc = await real_create_exec(*args, **kwargs)
            spawned_pids.append(proc.pid)
            return proc

        bot = make_bot()
        asyncio.create_subprocess_exec = tracking_create_exec
        try:
            rc, stdout, stderr = await bot._run_root_command(["sleep", "5"], timeout=0.2)
        finally:
            asyncio.create_subprocess_exec = real_create_exec
        assert rc is None, f"a genuinely slow command must report as timed out: rc={rc}"
        assert spawned_pids, "the sleep subprocess must have actually been spawned"
        pid = spawned_pids[0]
        try:
            os.kill(pid, 0)
            still_alive = True
        except ProcessLookupError:
            still_alive = False
        assert not still_alive, f"a killed-on-timeout subprocess (pid={pid}) must not remain running"
        print("Test 30 (subprocess timeout -- proses di-kill, tidak ada zombie/orphan tersisa) PASSED")

        print("\nALL /cekport REAL-LSOF SUBPROCESS & INJECTION-PROOF TESTS PASSED")

    print("\nALL /cekport LSOF TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
