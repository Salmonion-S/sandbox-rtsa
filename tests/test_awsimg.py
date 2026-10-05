import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from unittest import mock

from core import aws_asset_check as aac
from core.aws_asset_check import (
    AwsAssetRef, STATUS_ACCESSIBLE, STATUS_AWS_ERROR, STATUS_BLOCKED, STATUS_INACCESSIBLE,
    STATUS_REDIRECT, STATUS_TIMEOUT, check_aws_asset, check_aws_assets,
    collect_aws_asset_refs, extract_aws_urls_from_text, is_s3_hostname,
)

BUCKET = "https://newus-bucket.s3.ap-southeast-2.amazonaws.com"

class _FakeResponse:
    def __init__(self, status, headers=None, body=b"", reason="OK"):
        self.status = status
        self.headers = headers or {}
        self.reason = reason
        self.content = self
        self._body = body

    async def read(self, n=-1):
        return self._body[:n] if n and n > 0 else self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

class _FakeSession:

    def __init__(self, responder, delay=0.0):
        self._responder = responder
        self._delay = delay
        self.requested = []
        self.in_flight = 0
        self.peak_in_flight = 0
        self.allow_redirects_seen = []

    def get(self, url, timeout=None, allow_redirects=None, headers=None):
        self.requested.append(url)
        self.allow_redirects_seen.append(allow_redirects)
        session = self

        class _Ctx:
            async def __aenter__(self_inner):
                session.in_flight += 1
                session.peak_in_flight = max(session.peak_in_flight, session.in_flight)
                if session._delay:
                    await asyncio.sleep(session._delay)
                result = session._responder(url)
                if isinstance(result, Exception):
                    session.in_flight -= 1
                    raise result
                return result

            async def __aexit__(self_inner, *a):
                session.in_flight -= 1
                return False

        return _Ctx()

def public_dns(_host):
    return True

async def main():
    line = (
        '203.0.113.5 - - [01/Jan/2026:00:00:00 +0000] "GET '
        f'/_next/image?url={BUCKET}/rmepro/articles-images/60a.jpg&w=640&q=75 HTTP/2.0" '
        '200 512 "-" "Mozilla/5.0"'
    )
    urls = extract_aws_urls_from_text(line)
    assert urls == [f"{BUCKET}/rmepro/articles-images/60a.jpg"], urls
    print("Scenario 1 (AWS URL extracted from /_next/image?url=... query parameter) PASSED")

    encoded = (
        '"GET /_next/image?url=https%3A%2F%2Fnewus-bucket.s3.ap-southeast-2.amazonaws.com'
        '%2Frmepro%2Farticles-images%2Fd45.png&w=1080 HTTP/2.0"'
    )
    urls2 = extract_aws_urls_from_text(encoded)
    assert urls2 == [f"{BUCKET}/rmepro/articles-images/d45.png"], urls2
    print("Scenario 2 (percent-encoded AWS URL decoded and extracted) PASSED")

    for host in (
        "newus-bucket.s3.ap-southeast-2.amazonaws.com",
        "s3.ap-southeast-2.amazonaws.com",
        "bucket.s3.amazonaws.com",
        "s3.amazonaws.com",
        "my.dotted.bucket.s3.us-west-2.amazonaws.com",
    ):
        assert is_s3_hostname(host), host
    print("Scenario 3 (all standard S3 hostname shapes recognised) PASSED")

    for host in ("example.com", "s3.amazonaws.com.evil.test", "fake-s3.amazonaws.com",
                 "amazonaws.com", "nots3.example.com", ""):
        assert not is_s3_hostname(host), host
    noise = '"GET /img?url=https://cdn.example.com/a.png HTTP/1.1" 200 - "-" "-"'
    assert extract_aws_urls_from_text(noise) == []
    evil = '"GET /_next/image?url=https://s3.amazonaws.com.evil.test/x HTTP/1.1" 200'
    assert extract_aws_urls_from_text(evil) == [], "S3 lookalike host must not be extracted"
    print("Scenario 4 (non-AWS and lookalike S3 hosts excluded from extraction) PASSED")

    repeated = [f'"GET /_next/image?url={BUCKET}/a.jpg HTTP/2.0" 200' for _ in range(100)]
    refs, total = collect_aws_asset_refs([("rmepro.com", repeated)])
    assert len(refs) == 1 and total == 1, (refs, total)
    assert refs[0].occurrences == 100, refs[0]
    session = _FakeSession(lambda u: _FakeResponse(200))
    with mock.patch.object(aac, "_host_resolves_publicly", side_effect=public_dns):
        await check_aws_assets(session, refs)
    assert len(session.requested) == 1, f"100 log hits must produce 1 request, got {len(session.requested)}"
    print("Scenario 5 (URL seen 100x in log -> 1 ref, occurrences=100, exactly 1 HTTP check) PASSED")

    cases = [
        (200, b"", STATUS_ACCESSIBLE, None),
        (403, b"<Error><Code>AccessDenied</Code></Error>", STATUS_INACCESSIBLE, "Access Denied"),
        (404, b"<Error><Code>NoSuchKey</Code></Error>", STATUS_INACCESSIBLE, "No Such Key"),
        (500, b"<Error><Code>InternalError</Code></Error>", STATUS_AWS_ERROR, "Internal Error"),
    ]
    for status, body, expected, expected_reason in cases:
        s = _FakeSession(lambda u, st=status, b=body: _FakeResponse(st, body=b))
        with mock.patch.object(aac, "_host_resolves_publicly", side_effect=public_dns):
            r = await check_aws_asset(s, AwsAssetRef(f"{BUCKET}/x.jpg", "rmepro.com"))
        assert r.status == expected, (status, r.status)
        assert r.http_status == status, r
        if expected_reason:
            assert r.reason == expected_reason, (status, r.reason)
    print("Scenario 6-9 (200=ACCESSIBLE, 403/404=INACCESSIBLE, 500=AWS_ERROR; S3 <Code> surfaced as reason) PASSED")

    s = _FakeSession(lambda u: asyncio.TimeoutError())
    with mock.patch.object(aac, "_host_resolves_publicly", side_effect=public_dns):
        r = await check_aws_asset(s, AwsAssetRef(f"{BUCKET}/slow.jpg", "rmepro.com"), timeout_seconds=0.2)
    assert r.status == STATUS_TIMEOUT, r
    assert r.http_status is None and "0s" in r.reason or r.reason, r
    print(f"Scenario 10 (request timeout -> TIMEOUT, reason={r.reason!r}) PASSED")

    s = _FakeSession(lambda u: _FakeResponse(302, headers={"Location": "https://evil.test/steal"}))
    with mock.patch.object(aac, "_host_resolves_publicly", side_effect=public_dns):
        r = await check_aws_asset(s, AwsAssetRef(f"{BUCKET}/moved.jpg", "rmepro.com"))
    assert r.status == STATUS_REDIRECT and r.http_status == 302, r
    assert r.location == "https://evil.test/steal", r
    assert len(s.requested) == 1, f"redirect target must NOT be requested, got {s.requested}"
    assert all(v is False for v in s.allow_redirects_seen), s.allow_redirects_seen
    assert not any("evil.test" in u for u in s.requested), s.requested
    print("Scenario 11 (302 reported with Location, redirect target never requested) PASSED")

    for resolves in (False,):
        s = _FakeSession(lambda u: _FakeResponse(200))
        with mock.patch.object(aac, "_host_resolves_publicly", return_value=resolves):
            r = await check_aws_asset(s, AwsAssetRef(f"{BUCKET}/x.jpg", "rmepro.com"))
        assert r.status == STATUS_BLOCKED, r
        assert "private/internal" in r.reason, r.reason
        assert s.requested == [], "no request may be made to a private-resolving host"
    s = _FakeSession(lambda u: _FakeResponse(200))
    with mock.patch.object(aac, "_host_resolves_publicly", side_effect=public_dns):
        r = await check_aws_asset(s, AwsAssetRef("https://127.0.0.1/x", "rmepro.com"))
    assert r.status == STATUS_BLOCKED and s.requested == [], r
    r2 = await check_aws_asset(s, AwsAssetRef("file:///etc/passwd", "rmepro.com"))
    assert r2.status == STATUS_BLOCKED and s.requested == [], r2
    print("Scenario 12 (private-resolving host, 127.0.0.1 and non-http scheme all refused, zero requests) PASSED")

    many = [AwsAssetRef(f"{BUCKET}/img{i}.jpg", "rmepro.com") for i in range(20)]
    s = _FakeSession(lambda u: _FakeResponse(200), delay=0.05)
    with mock.patch.object(aac, "_host_resolves_publicly", side_effect=public_dns):
        out = await check_aws_assets(s, many, concurrency=5)
    assert len(out) == 20, len(out)
    assert s.peak_in_flight <= 5, f"concurrency exceeded the limit: peak={s.peak_in_flight}"
    print(f"Scenario 13 (20 URLs at concurrency=5: peak in-flight={s.peak_in_flight}, never above 5) PASSED")

    lines = [f'"GET /_next/image?url={BUCKET}/img{i}.jpg HTTP/2.0" 200' for i in range(57)]
    refs, total = collect_aws_asset_refs([("rmepro.com", lines)], max_urls=20)
    assert len(refs) == 20 and total == 57, (len(refs), total)
    print(f"Scenario 14 (57 unique URLs -> capped at {len(refs)}, total {total} still reported) PASSED")

    page1, t1 = collect_aws_asset_refs([("rmepro.com", lines)], max_urls=20, offset=0)
    page2, t2 = collect_aws_asset_refs([("rmepro.com", lines)], max_urls=20, offset=20)
    page3, t3 = collect_aws_asset_refs([("rmepro.com", lines)], max_urls=20, offset=40)
    past_end, t4 = collect_aws_asset_refs([("rmepro.com", lines)], max_urls=20, offset=57)
    assert (t1, t2, t3, t4) == (57, 57, 57, 57), "total_unique must be stable across pages"
    assert len(page1) == 20 and len(page2) == 20 and len(page3) == 17 and len(past_end) == 0
    urls_paged = [r.url for r in page1 + page2 + page3]
    assert len(set(urls_paged)) == 57, "pages must not overlap or drop URLs"
    assert urls_paged == [r.url for r in collect_aws_asset_refs([("rmepro.com", lines)], max_urls=0)[0]], (
        "walking the pages must reconstruct the same order as the full unpaged list"
    )
    print("Scenario 14b (offset pages the 57 URLs into 20+20+17, no overlap, no drop, order preserved) PASSED")

    multi = [
        ("rmepro.com", [f'"GET /_next/image?url={BUCKET}/rme.jpg HTTP/2.0" 200']),
        ("cbtgosmart.id", [f'"GET /_next/image?url={BUCKET}/cbt.jpg HTTP/2.0" 200']),
    ]
    refs_all, _ = collect_aws_asset_refs(multi)
    assert {r.domain for r in refs_all} == {"rmepro.com", "cbtgosmart.id"}, refs_all
    assert next(r for r in refs_all if r.url.endswith("rme.jpg")).domain == "rmepro.com"
    refs_one, _ = collect_aws_asset_refs([multi[0]])
    assert len(refs_one) == 1 and refs_one[0].domain == "rmepro.com", refs_one
    print("Scenario 15 (domain attributed from its own access log; filtering to one domain works) PASSED")

    from discord_integration.bot import RTSABot
    results = [
        aac.AwsAssetResult(f"{BUCKET}/bad.jpg", "rmepro.com", STATUS_INACCESSIBLE, 403, "Access Denied"),
        aac.AwsAssetResult(f"{BUCKET}/ok.jpg", "rmepro.com", STATUS_ACCESSIBLE, 200, "OK"),
    ]
    embed = RTSABot._format_awsimg_embed(results, total_unique=25, offset=0, shown=2, logs_scanned=3, domain_filter="")
    assert embed.title == "AWS IMAGE CHECK", embed.title
    assert len(embed.fields) == 1, [f.value for f in embed.fields]
    assert "bad.jpg" in embed.fields[0].value and "INACCESSIBLE" in embed.fields[0].value
    assert not any("ok.jpg" in f.value for f in embed.fields), "accessible (200) URLs must not be listed"
    assert "1 dari 2" in embed.description and "disembunyikan" in embed.description, embed.description
    assert "Dicek URL 1–2 dari 25" in embed.description, embed.description
    assert "Lanjut" in embed.description, "the more-pages note must point the operator at the Lanjut button"
    print("Scenario 16 (only non-2xx URLs listed; 200s hidden but counted; pagination note present) PASSED")

    all_ok = [
        aac.AwsAssetResult(f"{BUCKET}/a.jpg", "rmepro.com", STATUS_ACCESSIBLE, 200, "OK"),
        aac.AwsAssetResult(f"{BUCKET}/b.jpg", "rmepro.com", STATUS_ACCESSIBLE, 200, "OK"),
    ]
    embed_ok = RTSABot._format_awsimg_embed(all_ok, total_unique=2, offset=0, shown=2, logs_scanned=1, domain_filter="")
    assert embed_ok.fields == [] or len(embed_ok.fields) == 0, [f.value for f in embed_ok.fields]
    assert "Semua 2" in embed_ok.description and "tidak ada yang bermasalah" in embed_ok.description, embed_ok.description
    print("Scenario 16b (all-accessible page -> zero fields, explicit all-clear message) PASSED")

    embed_p2 = RTSABot._format_awsimg_embed(results, total_unique=25, offset=20, shown=2, logs_scanned=3, domain_filter="")
    assert "Dicek URL 21–22 dari 25" in embed_p2.description, embed_p2.description
    embed_last = RTSABot._format_awsimg_embed(results, total_unique=22, offset=20, shown=2, logs_scanned=3, domain_filter="")
    assert "Dicek URL" not in embed_last.description and "Lanjut" not in embed_last.description, (
        "on the final page there is nothing more to fetch, so no Lanjut prompt"
    )
    print("Scenario 16c (page range advances with offset; Lanjut prompt vanishes on the last page) PASSED")

    assert RTSABot._domain_label_for_log_path("/home/cbtgosmart/logs/nginx/access.log") == "cbtgosmart"
    assert RTSABot._domain_label_for_log_path("/home/elshanumtherapist/logs/nginx/access.log") == "elshanumtherapist"
    assert RTSABot._domain_label_for_log_path("/var/log/nginx/access.log") == "unknown"
    print("Scenario 17 (log path -> project label derived from /home/<user>/, never hardcoded) PASSED")

    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        for i in range(10_000):
            fh.write(f'1.2.3.4 - - [x] "GET /_next/image?url={BUCKET}/img{i}.jpg HTTP/2.0" 200\n')
        big_log = fh.name
    try:
        tail = RTSABot._read_log_tail(big_log, 500)
        assert len(tail) == 500, f"tail must be capped at 500 lines, got {len(tail)}"
        assert "img9999.jpg" in tail[-1], "the tail must be the END of the log, not the start"
        assert "img0.jpg" not in "".join(tail), "old lines must not be read"
        assert RTSABot._read_log_tail("/nonexistent/access.log", 100) == []
    finally:
        os.unlink(big_log)
    print("Scenario 18 (log read bounded to a tail of the newest lines; missing file degrades to empty) PASSED")

    import discord
    from unittest import mock as _mock

    from config.manager import CloudflareConfig, DiscordConfig, ResponseEngineConfig, RTSAConfig
    from core.event_bus import EventBus
    from discord_integration.bot import _AwsImgView

    _ADMIN = 555

    class _FakeResp:
        def __init__(self):
            self.messages = []
            self.deferred_thinking = None
        async def defer(self, ephemeral=False, thinking=False):
            self.deferred_thinking = thinking
        async def send_message(self, content=None, ephemeral=False, **kw):
            self.messages.append(content)

    class _FakeFollowup:
        def __init__(self):
            self.sent = []
        async def send(self, *a, **kw):
            self.sent.append(kw)

    class _FakeInter:
        def __init__(self, member):
            self.user = member
            self.response = _FakeResp()
            self.followup = _FakeFollowup()

    def _member(role_ids, mid=111):
        m = _mock.Mock(spec=discord.Member)
        m.roles = [type("R", (), {"id": r})() for r in role_ids]
        m.id = mid
        m.__str__ = _mock.Mock(return_value="op#1")
        return m

    cfg = RTSAConfig(response_engine=ResponseEngineConfig(), cloudflare=CloudflareConfig(enabled=False))
    disc = DiscordConfig(enabled=True, admin_role_ids=[_ADMIN])
    bot = RTSABot(disc, cfg, EventBus(), db_worker=None, supervisor=None)

    calls = []
    async def fake_awsimg(domain_filter="", offset=0, requested_by="unknown"):
        calls.append(offset)
        emb = discord.Embed(title="AWS IMAGE CHECK")
        return emb, offset + 20, 60
    bot._awsimg = fake_awsimg

    view = _AwsImgView(bot, domain_filter="rmepro.com", next_offset=20, total_unique=60, requested_by_id=111)
    inter = _FakeInter(_member([_ADMIN], mid=111))
    assert await view.interaction_check(inter) is True
    await next(c for c in view.children if isinstance(c, discord.ui.Button)).callback(inter)
    assert calls == [20], f"button must advance to its own next_offset, got {calls}"
    assert inter.response.deferred_thinking is True, (
        "the button must defer with thinking=True, otherwise its followup renders nothing"
    )
    sent = inter.followup.sent[0]
    assert isinstance(sent["view"], _AwsImgView), "another page remains (40<60) -> a fresh Lanjut button"
    assert sent["view"]._next_offset == 40, "the new button must point one page further"
    assert sent["ephemeral"] is True
    print("Scenario 19 (Lanjut advances by its offset and re-arms while pages remain) PASSED")

    calls.clear()
    view_last = _AwsImgView(bot, domain_filter="", next_offset=40, total_unique=60, requested_by_id=111)
    inter_last = _FakeInter(_member([_ADMIN], mid=111))
    await next(c for c in view_last.children if isinstance(c, discord.ui.Button)).callback(inter_last)
    assert calls == [40]
    assert inter_last.followup.sent[0]["view"] is None, "on the final page the Lanjut button is not re-attached"
    print("Scenario 19b (last page -> no further Lanjut button) PASSED")

    other = _FakeInter(_member([_ADMIN], mid=222))
    assert await view.interaction_check(other) is False
    assert "menjalankan command ini" in other.response.messages[0]
    view_self = _AwsImgView(bot, domain_filter="", next_offset=20, total_unique=60, requested_by_id=333)
    unauth = _FakeInter(_member([], mid=333))
    assert await view_self.interaction_check(unauth) is False
    assert "izin" in unauth.response.messages[0].lower()
    print("Scenario 19c (Lanjut refuses other members and members who lost the role) PASSED")

    print("\nALL /awsimg TESTS PASSED")

asyncio.run(asyncio.wait_for(main(), timeout=120))
