import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import PhpObfuscationDetectorConfig, SuspiciousUploadDetectorConfig
from core.php_analysis import analyze
from modules.php_obfuscation_detector import score_analysis
from modules.suspicious_upload_detector import score_file

_UPLOAD_CFG = SuspiciousUploadDetectorConfig()
_DANGEROUS = set(_UPLOAD_CFG.dangerous_extensions)
_OBF_CFG = PhpObfuscationDetectorConfig()

_JPEG_MAGIC = b"\xff\xd8\xff\xe0" + b"\x00" * 32


def obfuscation_score(source: str):
    return score_analysis(
        analyze("/tmp/sample.php", source),
        whole_file_entropy_threshold=_OBF_CFG.whole_file_entropy_threshold,
        string_entropy_threshold=_OBF_CFG.string_entropy_threshold,
        string_entropy_min_length=_OBF_CFG.string_entropy_min_length,
        variable_variable_density_threshold=_OBF_CFG.variable_variable_density_threshold,
        dynamic_call_density_threshold=_OBF_CFG.dynamic_call_density_threshold,
        chr_reconstruction_threshold=_OBF_CFG.chr_reconstruction_threshold,
    )


def main() -> None:
    score, evidence, mitre = score_file("invoice.php", b"<?php system($_GET['c']);", 0o644, _DANGEROUS)
    assert score >= _UPLOAD_CFG.min_confidence_to_report, (score, evidence)
    assert "dangerous_extension_in_upload_dir" in evidence
    assert "T1505.003" in mitre
    print("Test 1 [B] (suspicious_upload_detector: a .php file dropped in an upload directory scores above the reporting threshold) PASSED")

    score, evidence, _mitre = score_file("photo.php.jpg", _JPEG_MAGIC, 0o644, _DANGEROUS)
    assert "double_extension_bypass_pattern" in evidence, evidence
    assert score >= _UPLOAD_CFG.min_confidence_to_report, score
    print("Test 2 [B] (suspicious_upload_detector: the photo.php.jpg double-extension bypass is detected even though the final extension is benign) PASSED")

    score, evidence, _mitre = score_file("avatar.jpg", b"<?php eval($_POST['x']); ?>", 0o644, _DANGEROUS)
    assert "dangerous_content_marker_present" in evidence, evidence
    assert score >= _UPLOAD_CFG.min_confidence_to_report, score
    print("Test 3 [B] (suspicious_upload_detector: PHP source disguised behind a .jpg extension is caught by content-magic inspection, not by filename trust) PASSED")

    score, evidence, _mitre = score_file("holiday.jpg", _JPEG_MAGIC, 0o644, _DANGEROUS)
    assert score == 0, (score, evidence)
    assert evidence == [], evidence
    print("Test 4 [B] (suspicious_upload_detector: a genuine JPEG with matching magic bytes scores zero -- no false positive on normal uploads) PASSED")

    score, evidence, _mitre = score_file("report.pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3", 0o755, _DANGEROUS)
    assert "upload_file_executable_bit_set" in evidence, evidence
    print("Test 5 [B] (suspicious_upload_detector: an executable bit on an uploaded document is flagged) PASSED")

    benign_php = """<?php
function render_invoice($order_id) {
    $order = load_order($order_id);
    return view('invoice', ['order' => $order]);
}
"""
    score, evidence, _mitre = obfuscation_score(benign_php)
    assert score < _OBF_CFG.min_confidence_to_report, (score, evidence)
    print("Test 6 [B] (php_obfuscation_detector: ordinary readable application PHP stays below the reporting threshold) PASSED")

    variable_variable_php = "<?php " + " ".join(f"$${{'v{i}'}} = {i};" for i in range(6))
    score, evidence, _mitre = obfuscation_score(variable_variable_php)
    assert "high_variable_variable_density" in evidence, (score, evidence)
    print("Test 7 [B] (php_obfuscation_detector: dense variable-variable indirection is detected) PASSED")

    chr_php = "<?php $s = " + ".".join(f"chr({65 + (i % 26)})" for i in range(12)) + "; echo $s;"
    score, evidence, _mitre = obfuscation_score(chr_php)
    assert "char_code_string_reconstruction" in evidence, (score, evidence)
    assert score < _OBF_CFG.min_confidence_to_report, (
        f"one obfuscation signal on its own must stay below the reporting threshold so a single "
        f"weak indicator never becomes an alert: {score} {evidence}"
    )
    print("Test 8 [B] (php_obfuscation_detector: chr()-based reconstruction is recorded as evidence but a single signal alone stays below the reporting threshold) PASSED")

    packed_php = (
        "<?php $s = " + ".".join(f"chr({65 + (i % 26)})" for i in range(12)) + "; "
        + " ".join(f"$r{i} = $h{i}($s);" for i in range(6))
        + " $$s = 1; $${'a'} = 2; $${'b'} = 3;"
    )
    score, evidence, _mitre = obfuscation_score(packed_php)
    assert score >= _OBF_CFG.min_confidence_to_report, (score, evidence)
    assert len(evidence) >= 2, evidence
    print(f"Test 8b [B] (php_obfuscation_detector: chr() reconstruction corroborated by dynamic-call and variable-variable density crosses the threshold at score={score} with evidence={evidence}) PASSED")

    dynamic_php = "<?php " + " ".join(f"$f{i} = $fn{i}($a{i});" for i in range(7))
    score, evidence, _mitre = obfuscation_score(dynamic_php)
    assert isinstance(score, int) and 0 <= score <= 100
    print("Test 9 [B] (php_obfuscation_detector: dynamic-call density scoring stays within the bounded 0-100 range) PASSED")

    for score_fn, sample in (
        (obfuscation_score, ""),
        (obfuscation_score, "<?php"),
    ):
        result = score_fn(sample)
        assert isinstance(result[0], int) and 0 <= result[0] <= 100
    assert score_file("", b"", 0o644, _DANGEROUS)[0] == 0
    print("Test 10 [B] (both detectors handle empty and truncated input without raising -- no crash surface on malformed files) PASSED")

    print("\nALL UPLOAD/OBFUSCATION DETECTOR TESTS PASSED")


main()
