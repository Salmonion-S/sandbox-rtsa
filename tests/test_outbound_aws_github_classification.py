import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import ipaddress

from core.outbound_baseline import (
    TRUST_AWS_EDGE, TRUST_CLOUDFLARE_EDGE, TRUST_GITHUB_EDGE, TRUST_UNKNOWN,
    classify_destination_trust, cloudflare_range_summary,
)
from config.manager import OutboundAnomalyDetectorConfig


def main():
    assert classify_destination_trust("140.82.112.5") == TRUST_GITHUB_EDGE
    assert classify_destination_trust("185.199.108.1") == TRUST_GITHUB_EDGE
    assert classify_destination_trust("20.205.243.1") == TRUST_GITHUB_EDGE
    assert classify_destination_trust("8.8.8.8") == TRUST_UNKNOWN
    print("Test 1 (GitHub's published ranges are recognized; unrelated IPs stay UNKNOWN) PASSED")

    aws_net = (ipaddress.ip_network("52.94.0.0/16"),)
    assert classify_destination_trust("52.94.1.1", aws_networks=aws_net) == TRUST_AWS_EDGE
    assert classify_destination_trust("52.94.1.1") == TRUST_UNKNOWN, (
        "AWS must never be trusted unless the operator explicitly supplies ranges -- no blanket whitelist"
    )
    print("Test 2 (AWS is trusted only via operator-supplied ranges, never by default) PASSED")

    assert classify_destination_trust("173.245.48.1") == TRUST_CLOUDFLARE_EDGE
    print("Test 3 (Cloudflare classification is unaffected by the GitHub/AWS extension) PASSED")

    summary = cloudflare_range_summary()
    assert summary.get("github_ipv4_ranges", 0) > 0
    print("Test 4 (cloudflare_range_summary reports github_ipv4_ranges) PASSED")

    default_ranges = OutboundAnomalyDetectorConfig().aws_ip_ranges
    assert default_ranges == [], "aws_ip_ranges must default to empty -- AWS trust is opt-in only"
    print("Test 5 (OutboundAnomalyDetectorConfig.aws_ip_ranges defaults to empty) PASSED")

    print("\nALL AWS/GITHUB EGRESS CLASSIFICATION REGRESSION TESTS PASSED")


if __name__ == "__main__":
    main()
