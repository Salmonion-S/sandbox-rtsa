from __future__ import annotations

import asyncio
import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)
os.chdir(_REPO)

from core.lb_database import (
    LEVEL_AUTH, LEVEL_DNS, LEVEL_PROTOCOL, LEVEL_TCP, DbConfigFacts, DbConnectivity, DbMode, VersionFacts, classify_host,
    compare_versions, compute_connection_budget, db_findings, detect_db_config, detect_stateful_dependencies,
    effective_minimum_level, evaluate_stateful, infer_db_mode, parse_wp_config, probe_db_connectivity, version_findings,
)


def test_1_config_detection_never_keeps_credentials() -> None:
    url = detect_db_config({"DATABASE_URL": "postgres://appuser:s3cr3tPass@db.internal:5432/appdb?sslmode=require&connection_limit=12"})
    assert (url.engine, url.host, url.port, url.name, url.tls_required, url.pool_size) == ("postgresql", "db.internal", 5432, "appdb", True, 12)
    assert url.user_present and url.password_present
    assert "s3cr3tPass" not in str(url.to_dict()) and "appuser" not in str(url.to_dict()), "credentials are never kept"
    laravel = detect_db_config({"DB_CONNECTION": "mysql", "DB_HOST": "10.0.0.5", "DB_PORT": "3306", "DB_DATABASE": "shop", "DB_USERNAME": "u", "DB_PASSWORD": "p", "DB_POOL_MAX": "25"})
    assert (laravel.engine, laravel.host, laravel.port, laravel.locality, laravel.pool_size) == ("mysql", "10.0.0.5", 3306, "PRIVATE", 25)
    assert detect_db_config({"MONGODB_URI": "mongodb+srv://u:p@cluster0.abcd.mongodb.net/app"}).locality == "MANAGED"
    assert detect_db_config({"DB_HOST": "db.x.internal", "DB_PORT": "5432"}).engine == "postgresql"
    assert detect_db_config({"PGHOST": "pg.internal"}).engine == "postgresql"
    sqlite = detect_db_config({"DB_CONNECTION": "sqlite", "DB_DATABASE": "/home/u/db.sqlite"})
    assert sqlite.engine == "sqlite" and sqlite.locality == "LOCAL_FILE"
    wp = detect_db_config({}, parse_wp_config("define( 'DB_NAME', 'wpdb' );\ndefine('DB_USER','u');\ndefine('DB_PASSWORD','pw');\ndefine('DB_HOST','localhost:3307');"))
    assert (wp.engine, wp.host, wp.port, wp.name, wp.locality) == ("mysql", "localhost", 3307, "wpdb", "LOCAL")
    assert detect_db_config({}) is None and detect_db_config({"APP_ENV": "production"}) is None
    replica = detect_db_config({"DB_HOST": "10.0.0.5", "DB_CONNECTION": "mysql", "DB_READ_HOST": "10.0.0.6"})
    assert replica.read_replica_configured
    assert classify_host("127.0.0.1") == "LOCAL" and classify_host("localhost") == "LOCAL" and classify_host("/var/run/mysqld.sock") == "LOCAL"
    assert classify_host("10.1.2.3") == "PRIVATE" and classify_host("100.64.1.1") == "PRIVATE" and classify_host("8.8.8.8") == "PUBLIC"
    assert classify_host("mydb.abc.rds.amazonaws.com") == "MANAGED" and classify_host("db.example.org") == "HOSTNAME"
    print("Test 1 (DB engine/host/port/name/pool detected from URL, variable and wp-config forms; credentials are never retained) PASSED")


def test_2_db_mode_inference_and_declaration() -> None:
    shared = detect_db_config({"DB_CONNECTION": "mysql", "DB_HOST": "10.0.0.5"})
    assert infer_db_mode(shared).mode == DbMode.PRIMARY_SHARED and not infer_db_mode(shared).blocks_multi_origin
    local = detect_db_config({"DB_CONNECTION": "mysql", "DB_HOST": "127.0.0.1"})
    decision = infer_db_mode(local)
    assert decision.mode == DbMode.LOCAL_PER_ORIGIN and decision.blocks_multi_origin
    assert infer_db_mode(detect_db_config({"DB_CONNECTION": "sqlite"})).mode == DbMode.LOCAL_PER_ORIGIN
    assert infer_db_mode(None).mode == DbMode.UNKNOWN and infer_db_mode(None).blocks_multi_origin
    assert infer_db_mode(detect_db_config({"DATABASE_URL": "postgres://u:p@x.db.ondigitalocean.com:25060/app"})).mode == DbMode.EXTERNAL_MANAGED
    assert infer_db_mode(detect_db_config({"DB_CONNECTION": "mysql", "DB_HOST": "10.0.0.5", "DB_READ_HOST": "10.0.0.6"})).mode == DbMode.READ_REPLICAS
    assert infer_db_mode(shared, "read_replicas").mode == DbMode.READ_REPLICAS and infer_db_mode(shared, "read_replicas").source == "declared"
    multi = infer_db_mode(shared, "MULTI_PRIMARY")
    assert multi.mode == DbMode.MULTI_PRIMARY and multi.warnings and "never configures" in multi.warnings[0]
    for inferred in (shared, local, None):
        assert infer_db_mode(inferred).mode != DbMode.MULTI_PRIMARY, "multi-primary is never inferred or created automatically"
    assert infer_db_mode(shared, "SHARDED").mode == DbMode.UNKNOWN
    assert infer_db_mode(local, "PRIMARY_SHARED").blocks_multi_origin is False, "an explicit operator declaration overrides the inference"
    print("Test 2 (PRIMARY_SHARED default; LOCAL_PER_ORIGIN blocks; managed/replica detected; MULTI_PRIMARY only by explicit declaration) PASSED")


class FakeServer:
    def __init__(self, handler) -> None:
        self._handler = handler
        self.server = None
        self.port = 0

    async def __aenter__(self) -> "FakeServer":
        self.server = await asyncio.start_server(self._handler, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc) -> None:
        self.server.close()
        await self.server.wait_closed()


async def mysql_handler(reader, writer) -> None:
    writer.write(b"\x4a\x00\x00\x00\x0a8.0.36\x00" + b"\x00" * 20)
    await writer.drain()
    writer.close()


def postgres_handler(answer: bytes):
    async def handler(reader, writer) -> None:
        await reader.readexactly(8)
        writer.write(answer)
        await writer.drain()
        writer.close()
    return handler


async def redis_handler(reader, writer) -> None:
    await reader.readline()
    writer.write(b"+PONG\r\n")
    await writer.drain()
    writer.close()


async def silent_handler(reader, writer) -> None:
    await asyncio.sleep(0.5)
    writer.close()


async def garbage_handler(reader, writer) -> None:
    writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    await writer.drain()
    writer.close()


def facts_for(engine: str, port: int, **kw) -> DbConfigFacts:
    return DbConfigFacts(engine=engine, host="127.0.0.1", port=port, name="app", locality="LOCAL", **kw)


async def test_3_connectivity_levels() -> None:
    async with FakeServer(mysql_handler) as srv:
        result = await probe_db_connectivity(facts_for("mysql", srv.port), origin_id="server1", timeout=1.5)
        assert result.level == LEVEL_PROTOCOL and result.protocol_ok and result.tcp_ok and result.dns_ok and result.ok
        assert result.latency_ms is not None and result.auth_ok is None, "authentication is NOT_VERIFIED without a query probe"
        assert result.meets(LEVEL_PROTOCOL) and not result.meets(LEVEL_AUTH)
    async with FakeServer(postgres_handler(b"S")) as srv:
        result = await probe_db_connectivity(facts_for("postgresql", srv.port), timeout=1.5)
        assert result.level == LEVEL_PROTOCOL and result.tls_supported is True
    async with FakeServer(postgres_handler(b"N")) as srv:
        ok = await probe_db_connectivity(facts_for("postgresql", srv.port), timeout=1.5)
        assert ok.level == LEVEL_PROTOCOL and ok.tls_supported is False
        required = await probe_db_connectivity(facts_for("postgresql", srv.port, tls_required=True), timeout=1.5)
        assert not required.ok and "TLS is required" in required.reason
    async with FakeServer(redis_handler) as srv:
        assert (await probe_db_connectivity(facts_for("redis", srv.port), timeout=1.5)).level == LEVEL_PROTOCOL
    async with FakeServer(garbage_handler) as srv:
        bad = await probe_db_connectivity(facts_for("mysql", srv.port), timeout=1.5)
        assert bad.level == LEVEL_TCP and bad.protocol_ok is False and not bad.ok, "a TCP listener that is not the database is not healthy"
    async with FakeServer(silent_handler) as srv:
        slow = await probe_db_connectivity(facts_for("mysql", srv.port), timeout=0.2)
        assert not slow.ok and slow.level == LEVEL_TCP
    async with FakeServer(mysql_handler) as srv:
        mongo = await probe_db_connectivity(facts_for("mongodb", srv.port), timeout=1.5)
        assert mongo.level == LEVEL_TCP and mongo.protocol_ok is None and mongo.ok, "engines without a handshake are accepted at TCP level only"
        assert effective_minimum_level("mongodb", LEVEL_PROTOCOL) == LEVEL_TCP and effective_minimum_level("mysql", LEVEL_PROTOCOL) == LEVEL_PROTOCOL
        assert mongo.meets(effective_minimum_level("mongodb", LEVEL_PROTOCOL))
    closed = await probe_db_connectivity(facts_for("mysql", 1), timeout=0.5)
    assert closed.level == LEVEL_DNS and closed.tcp_ok is False and not closed.ok
    unresolved = await probe_db_connectivity(DbConfigFacts(engine="mysql", host="no-such-host.invalid", port=3306), timeout=0.8)
    assert unresolved.dns_ok is False and unresolved.level == "NONE"
    print("Test 3 (DNS/TCP/protocol/TLS connectivity levels measured against real sockets; non-database listeners and timeouts are not healthy) PASSED")


async def test_4_probe_safety_and_query_probe() -> None:
    forbidden = await probe_db_connectivity(DbConfigFacts(engine="mysql", host="169.254.169.254", port=3306), timeout=0.5)
    assert forbidden.level == "NONE" and "never probed" in forbidden.reason
    calls = []

    async def connector(host, port, timeout):
        calls.append(host)
        raise AssertionError("a forbidden target must not be dialled")

    await probe_db_connectivity(DbConfigFacts(engine="mysql", host="169.254.169.254", port=3306), timeout=0.5, connector=connector)
    await probe_db_connectivity(DbConfigFacts(engine="mysql", host="0.0.0.0", port=3306), timeout=0.5, connector=connector)
    assert not calls
    sqlite = await probe_db_connectivity(DbConfigFacts(engine="sqlite", locality="LOCAL_FILE"), timeout=0.5)
    assert "local file" in sqlite.reason

    async with FakeServer(mysql_handler) as srv:
        async def good(facts, timeout):
            return True, True, "SELECT 1 ok (read-only)"

        async def denied(facts, timeout):
            return False, None, "access denied for user"

        authed = await probe_db_connectivity(facts_for("mysql", srv.port), timeout=1.0, query_probe=good)
        assert authed.level == LEVEL_AUTH and authed.auth_ok and authed.read_only_ok and authed.meets(LEVEL_AUTH)
        rejected = await probe_db_connectivity(facts_for("mysql", srv.port), timeout=1.0, query_probe=denied)
        assert rejected.auth_ok is False and not rejected.ok, "a reachable database that rejects the credentials is not usable"
    print("Test 4 (link-local/unspecified targets are never dialled; SELECT 1 probe raises the level to AUTH, rejected credentials are unhealthy) PASSED")


def test_5_connection_budget() -> None:
    three = compute_connection_budget(existing_origins=0, added_origins=3, pool_per_origin=100, max_connections=500, current_usage=0, ratio=0.8)
    assert three.status == "OK" and three.projected_total == 300 and "3 origins x 100 pool = 300" in three.detail
    risk = compute_connection_budget(existing_origins=1, added_origins=3, pool_per_origin=100, max_connections=300, current_usage=50, ratio=0.8)
    assert risk.status == "DB_CAPACITY_RISK" and risk.max_added_origins == 1 and risk.ceiling == 240
    unknown = compute_connection_budget(existing_origins=0, added_origins=2, pool_per_origin=0, max_connections=0, current_usage=0, ratio=0.8)
    assert unknown.status == "NOT_VERIFIED" and "not known" in unknown.detail
    exact = compute_connection_budget(existing_origins=0, added_origins=2, pool_per_origin=40, max_connections=100, current_usage=0, ratio=0.8)
    assert exact.status == "OK" and exact.max_added_origins == 2
    print("Test 5 (origins x pool vs max_connections and current usage: OK / DB_CAPACITY_RISK with how many origins fit / NOT_VERIFIED when unknown) PASSED")


def test_6_version_consistency() -> None:
    facts = [VersionFacts("server1", "2.5", "42"), VersionFacts("server2", "2.5", "42"), VersionFacts("server3", "2.4", "41")]
    decision = compare_versions(facts)
    assert decision.reference == ("2.5", "42") and decision.status_by_origin == {"server1": "MATCH", "server2": "MATCH", "server3": "MISMATCH"}
    findings = version_findings(decision, facts)
    assert len(findings) == 1 and findings[0].code == "VERSION_MISMATCH" and findings[0].blocking and findings[0].origin_id == "server3"
    tie = compare_versions([VersionFacts("a", "2.5", "42"), VersionFacts("b", "2.4", "41")])
    assert tie.ambiguous and set(tie.status_by_origin.values()) == {"AMBIGUOUS"}
    preferred = compare_versions([VersionFacts("a", "2.5", "42"), VersionFacts("b", "2.4", "41")], preferred_reference="a")
    assert not preferred.ambiguous and preferred.status_by_origin == {"a": "MATCH", "b": "MISMATCH"}
    unreported = compare_versions([VersionFacts("a", "2.5", "42"), VersionFacts("b", "", "")])
    assert unreported.status_by_origin["b"] == "UNREPORTED" and version_findings(unreported, [VersionFacts("a", "2.5", "42"), VersionFacts("b", "", "")])[0].blocking
    none_known = compare_versions([VersionFacts("a"), VersionFacts("b")])
    assert not none_known.comparable
    assert version_findings(none_known, [])[0].code == "VERSION_UNVERIFIED" and not version_findings(none_known, [])[0].blocking
    print("Test 6 (application/schema version consistency: majority reference, mismatch blocks, tie is ambiguous, unreported is unproven) PASSED")


def test_7_stateful_detection() -> None:
    def kinds(env, deps=(), uploads=()):
        return {f.kind for f in detect_stateful_dependencies(env, deps, uploads)}

    assert kinds({"SESSION_DRIVER": "file"}) == {"sessions"}
    assert kinds({"SESSION_DRIVER": "redis"}) == set() and kinds({"SESSION_DRIVER": "database"}) == set()
    assert kinds({}, ["express-session"]) == {"sessions"}
    assert kinds({}, ["express-session", "connect-redis"]) == set()
    assert kinds({}, ["express-session", "jsonwebtoken"]) == set(), "token sessions are stateless"
    assert kinds({}, [], ["uploads", "storage/app/public"]) == {"uploads"}
    assert kinds({"FILESYSTEM_DISK": "s3"}, [], ["uploads"]) == set(), "object storage is a shared store"
    assert kinds({"FILESYSTEM_DISK": "local"}) == {"uploads"}
    assert kinds({"CACHE_DRIVER": "file"}) == {"cache"}
    assert kinds({}, ["socket.io"]) == {"websocket"} and kinds({}, ["socket.io", "@socket.io/redis-adapter"]) == set()
    assert kinds({"QUEUE_CONNECTION": "file"}) == {"queue"} and kinds({"QUEUE_CONNECTION": "redis"}) == set()
    findings = detect_stateful_dependencies({"SESSION_DRIVER": "file", "CACHE_DRIVER": "file"}, [], [])
    multi = evaluate_stateful(findings, {}, 3)
    blocking = [f for f in multi if f.blocking]
    assert [f.code for f in blocking] == ["SHARED_STATE_REQUIRED"] and "session affinity is not enabled automatically" in blocking[0].message
    cache = [f for f in multi if not f.blocking]
    assert cache and cache[0].severity == "WARNING", "a per-origin cache is reported but does not block"
    single = evaluate_stateful(findings, {}, 1)
    assert not any(f.blocking for f in single), "one origin needs no shared state"
    cleared = evaluate_stateful(findings, {"sessions": "shared", "cache": "none"}, 3)
    assert not any(f.blocking for f in cleared) and any(f.code == "SHARED_STATE_DECLARED" for f in cleared)
    print("Test 7 (local sessions/uploads/cache/queue/WebSocket detected; shared stores recognised; blocks only multi-origin; explicit declaration clears) PASSED")


def test_8_db_findings() -> None:
    from core.lb_database import DbModeDecision

    facts_a = DbConfigFacts(engine="postgresql", host="db.internal", port=5432, name="app")
    facts_b = DbConfigFacts(engine="postgresql", host="other.internal", port=5432, name="app")
    ok = DbConnectivity(origin_id="server1", level=LEVEL_PROTOCOL, tcp_ok=True, protocol_ok=True)
    down = DbConnectivity(origin_id="server2", level=LEVEL_TCP, tcp_ok=True, protocol_ok=False, reason="no greeting")
    decision = DbModeDecision(DbMode.PRIMARY_SHARED, "inferred", "remote host")
    findings = db_findings(decision, {"server1": ok, "server2": down}, ["server1", "server2"], LEVEL_PROTOCOL, True, {"server1": facts_a, "server2": facts_a})
    assert [f.origin_id for f in findings if f.code == "DB_UNREACHABLE"] == ["server2"]
    assert any(f.code == "DB_TARGET_MISMATCH" and f.blocking for f in db_findings(decision, {}, ["a", "b"], LEVEL_PROTOCOL, False, {"a": facts_a, "b": facts_b}))
    local = DbModeDecision(DbMode.LOCAL_PER_ORIGIN, "inferred", "local", True)
    assert [f.code for f in db_findings(local, {}, ["a", "b"], LEVEL_PROTOCOL, False, {})] == ["DB_LOCAL_PER_ORIGIN"]
    assert db_findings(local, {}, ["a"], LEVEL_PROTOCOL, False, {}) == [], "a single origin is not blocked by a local database"
    unknown = DbModeDecision(DbMode.UNKNOWN, "inferred", "no config", True)
    assert [f.code for f in db_findings(unknown, {}, ["a", "b"], LEVEL_PROTOCOL, False, {})] == ["DB_MODE_UNKNOWN"]
    print("Test 8 (per-origin connectivity failures, differing DB targets, LOCAL_PER_ORIGIN and UNKNOWN produce the right blocking findings) PASSED")


async def main() -> None:
    test_1_config_detection_never_keeps_credentials()
    test_2_db_mode_inference_and_declaration()
    await test_3_connectivity_levels()
    await test_4_probe_safety_and_query_probe()
    test_5_connection_budget()
    test_6_version_consistency()
    test_7_stateful_detection()
    test_8_db_findings()
    print("\nALL LOAD BALANCER DATABASE TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
