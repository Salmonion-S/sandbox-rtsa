import os
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.file_identity import hash_file, stat_identity


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        small_path = os.path.join(tmp, "small.txt")
        with open(small_path, "wb") as f:
            f.write(b"a" * 1000)

        big_path = os.path.join(tmp, "big.bin")
        with open(big_path, "wb") as f:
            f.write(b"b" * 5000)

        assert hash_file(small_path, max_bytes=2000) is not None, "a file under the byte cap must still hash normally"
        assert hash_file(big_path, max_bytes=2000) is None, (
            "a file over the byte cap must never be read/hashed -- hash_file must bail out cheaply "
            "via a size check before opening/reading the file"
        )
        print("Scenario 1 (hash_file respects max_bytes -- oversized files are never read) PASSED")

        identity_small = stat_identity(small_path, max_hash_bytes=2000)
        assert identity_small is not None
        assert identity_small.sha256 is not None, "a file under the cap must get a real sha256"
        assert identity_small.hash_skipped_reason is None
        print("Scenario 2 (stat_identity computes a real hash for files under the cap) PASSED")

        identity_big = stat_identity(big_path, max_hash_bytes=2000)
        assert identity_big is not None, (
            "a file over the cap must still produce a valid FileIdentity (metadata-only) -- it must "
            "never look like a deleted/unreadable file just because hashing was skipped for size"
        )
        assert identity_big.sha256 is None
        assert identity_big.hash_skipped_reason == "size_exceeded"
        assert identity_big.size == 5000, "size/mtime/mode metadata must still be captured even when the hash is skipped"
        assert identity_big.mode is not None
        print("Scenario 3 (stat_identity degrades to metadata-only for oversized files, never mistaken for a deletion) PASSED")

        identity_uncapped = stat_identity(big_path)
        assert identity_uncapped is not None
        assert identity_uncapped.sha256 is not None, "max_hash_bytes=None (the default) must preserve the original always-hash behavior"
        print("Scenario 4 (max_hash_bytes=None -- fully backward compatible, original always-hash behavior) PASSED")

        print("\nALL FIM HASH SIZE BUDGET TESTS PASSED")


main()
