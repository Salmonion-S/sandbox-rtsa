import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import shutil
import tempfile
from pathlib import Path

from core.fim_risk_classifier import classify_risk
from core.php_analysis import find_php_files

BASE = os.path.join(tempfile.gettempdir(), "rtsa_php_ext_discovery_test")


def main():
    shutil.rmtree(BASE, ignore_errors=True)
    project = Path(BASE) / "proj"
    (project / "webroot").mkdir(parents=True)
    (project / "vendor" / "some-lib").mkdir(parents=True)

    dotphp = project / "webroot" / "index.php"
    dotphp.write_text("<?php echo 1;", encoding="utf-8")
    dotphtml_shell = project / "webroot" / "shell.phtml"
    dotphtml_shell.write_text("<?php system($_GET['c']); ?>", encoding="utf-8")
    dotphp5_shell = project / "webroot" / "backup.php5"
    dotphp5_shell.write_text("<?php eval($_POST['x']); ?>", encoding="utf-8")
    dotphar = project / "webroot" / "tool.phar"
    dotphar.write_text("<?php // phar stub", encoding="utf-8")
    not_php = project / "webroot" / "readme.txt"
    not_php.write_text("hello", encoding="utf-8")
    vendor_php = project / "vendor" / "some-lib" / "lib.php"
    vendor_php.write_text("<?php // vendor", encoding="utf-8")

    found = set(find_php_files(str(project), max_depth=8, ignore_path_substrings=[]))

    assert str(dotphp) in found, "plain .php must still be discovered (no regression)"
    print("Scenario 1 (.php still discovered) PASSED")

    assert str(dotphtml_shell) in found, (
        f".phtml webshell must be discovered outside an uploads directory -- "
        f"section 5 requires PHP-family, not just .php: {found}"
    )
    print("Scenario 2 (.phtml webshell discovered) PASSED")

    assert str(dotphp5_shell) in found, ".php5 file must be discovered"
    assert str(dotphar) in found, ".phar file must be discovered"
    print("Scenario 3 (.php5 and .phar discovered) PASSED")

    assert str(not_php) not in found, "non-PHP files must not be swept into php_source discovery"
    print("Scenario 4 (non-PHP file correctly excluded) PASSED")

    assert str(vendor_php) not in found, (
        "vendor/ stays excluded from php_source discovery (existing, deliberate scale tradeoff, "
        "unchanged by this fix)"
    )
    print("Scenario 5 (vendor/ exclusion unchanged) PASSED")

    result = classify_risk(
        path=str(dotphtml_shell), change_type="created", project_root=str(project),
    )
    assert result is not None, ".phtml under webroot must still receive PHP risk scoring"
    print("Scenario 6 (.phtml receives PHP-aware risk classification) PASSED")

    print("\nALL PHP EXTENSION DISCOVERY TESTS PASSED")


main()
