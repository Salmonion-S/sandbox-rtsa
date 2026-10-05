from __future__ import annotations

import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.process_fingerprint as process_fingerprint_module
from core.process_fingerprint import compute_fingerprint, hash_executable


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="rtsa-hashcache-") as tmp:
        path = os.path.join(tmp, "some-binary")
        with open(path, "wb") as f:
            f.write(b"original binary content")

        read_calls = {"n": 0}
        real_open = process_fingerprint_module.open if hasattr(process_fingerprint_module, "open") else open

        def counting_open(file, *args, **kwargs):
            if file == path:
                read_calls["n"] += 1
            return real_open(file, *args, **kwargs)

        process_fingerprint_module.open = counting_open
        try:
            first = hash_executable(path)
            assert first is not None and len(first) == 64
            assert read_calls["n"] == 1, f"first call must read the file exactly once, got {read_calls['n']}"
            cache_key = (path, process_fingerprint_module._DEFAULT_HASH_MAX_BYTES)
            assert cache_key in process_fingerprint_module._hash_cache
            print("Test 1 (hash_executable computes and caches a digest keyed by path+max_bytes, reading the file once) PASSED")

            second = hash_executable(path)
            assert second == first, "unchanged file must yield the identical cached digest"
            assert read_calls["n"] == 1, (
                f"a second hash_executable() call on an unchanged file must not re-read it -- "
                f"read count grew to {read_calls['n']}"
            )
            print("Test 2 (unchanged file -- second call reuses the cached digest, zero additional file reads) PASSED")

            time.sleep(0.01)
            with open(path, "wb") as f:
                f.write(b"REPLACED malicious binary content, much longer than the original")
            os.utime(path, None)
            third = hash_executable(path)
            assert third != first, "a genuinely swapped binary must produce a different digest -- cache must never mask this"
            assert read_calls["n"] == 2, f"a changed binary must trigger exactly one fresh re-read, got {read_calls['n']}"
            print("Test 3 (binary content changed on disk -- cache correctly invalidates and re-reads exactly once) PASSED")

            with open(path, "wb") as f:
                f.write(b"A" * 100 + b"B" * 100)
            full_hash = hash_executable(path, max_bytes=1_000_000)
            truncated_hash = hash_executable(path, max_bytes=50)
            assert full_hash != truncated_hash, "different max_bytes must not share a cache entry"
            print("Test 4 (different max_bytes for the same path are cached independently, never collide) PASSED")
        finally:
            process_fingerprint_module.open = real_open

        missing_path = os.path.join(tmp, "does-not-exist")
        assert hash_executable(missing_path) is None
        assert (missing_path, process_fingerprint_module._DEFAULT_HASH_MAX_BYTES) not in process_fingerprint_module._hash_cache
        print("Test 5 (missing file -> None, gracefully, nothing cached) PASSED")

        with open(path, "wb") as f:
            f.write(b"stable content for fingerprint test")
        fp1 = compute_fingerprint(exe=path, uid=1000, username="testuser", cmdline="testuser proc", cwd="/tmp")
        fp2 = compute_fingerprint(exe=path, uid=1000, username="testuser", cmdline="testuser proc", cwd="/tmp")
        assert fp1.exe_sha256 == fp2.exe_sha256 and fp1.fingerprint == fp2.fingerprint
        assert fp1.exe_sha256 is not None
        print("Test 6 (compute_fingerprint's exe_sha256 is stable and cache-backed across repeated calls) PASSED")

    print("\nALL PROCESS FINGERPRINT HASH CACHE TESTS PASSED")


main()
