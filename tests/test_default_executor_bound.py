import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import asyncio
import threading
import time

from config.manager import ResourceGovernorConfig
from core.cpu_governor import configure_cpu_governor, get_cpu_governor, install_bounded_default_executor


def _busy(seconds: float) -> None:
    time.sleep(seconds)


async def main() -> None:
    governor = get_cpu_governor()

    configure_cpu_governor(ResourceGovernorConfig(enabled=True, default_executor_workers=3))
    assert governor.default_executor_workers == 3, (
        f"an explicit default_executor_workers config value must be honoured, got {governor.default_executor_workers}"
    )
    print("Scenario 1 (explicit default_executor_workers config value is honoured) PASSED")

    configure_cpu_governor(ResourceGovernorConfig(enabled=True, default_executor_workers=0))
    auto = governor.default_executor_workers
    assert 2 <= auto <= 8, f"auto-sized default executor must stay within [2, 8], got {auto}"
    cpu_count = os.cpu_count() or 4
    assert auto == max(2, min(8, cpu_count)), (
        f"auto sizing must follow max(2, min(8, cpu_count)) -- cpu_count={cpu_count} expected "
        f"{max(2, min(8, cpu_count))}, got {auto}"
    )
    print(f"Scenario 2 (auto-sized default_executor_workers={auto} for cpu_count={cpu_count}, bounded [2,8]) PASSED")

    loop = asyncio.get_running_loop()
    configure_cpu_governor(ResourceGovernorConfig(enabled=True, default_executor_workers=2))
    install_bounded_default_executor(loop)

    thread_name = await loop.run_in_executor(None, lambda: threading.current_thread().name)
    assert thread_name.startswith("rtsa-default"), (
        f"loop.run_in_executor(None, ...) must now draw from RTSA's own bounded pool, "
        f"got thread name {thread_name!r}"
    )
    print("Scenario 3 (loop.run_in_executor(None, ...) draws from RTSA's installed bounded pool) PASSED")

    n_concurrent = 6
    active_at_once = []
    lock = threading.Lock()
    counter = {"active": 0, "peak": 0}

    def track_and_wait() -> None:
        with lock:
            counter["active"] += 1
            counter["peak"] = max(counter["peak"], counter["active"])
        time.sleep(0.15)
        with lock:
            counter["active"] -= 1

    await asyncio.gather(*(loop.run_in_executor(None, track_and_wait) for _ in range(n_concurrent)))
    assert counter["peak"] <= 2, (
        f"with default_executor_workers=2, at most 2 of {n_concurrent} concurrent "
        f"run_in_executor(None, ...) jobs may be running at once, observed peak={counter['peak']}"
    )
    print(f"Scenario 4 (concurrent run_in_executor(None, ...) jobs capped at peak={counter['peak']} <= 2) PASSED")

    old_executor = governor._default_executor
    install_bounded_default_executor(loop)
    new_executor = governor._default_executor
    assert new_executor is not old_executor, "re-installing must replace the executor, not reuse it"
    assert old_executor._shutdown, "the previous default executor must be shut down when replaced"
    print("Scenario 5 (re-installing the default executor shuts down the previous one) PASSED")

    governor.shutdown()
    assert governor._default_executor is None, "governor.shutdown() must clear the default executor reference"
    assert governor._executor is None, "governor.shutdown() must clear the scan-pool executor reference too"
    print("Scenario 6 (governor.shutdown() tears down both the scan pool and the default executor) PASSED")

    governor.reset_for_tests()
    configure_cpu_governor(ResourceGovernorConfig(enabled=True))

    print("\nALL DEFAULT-EXECUTOR BOUND REGRESSION TESTS PASSED")


asyncio.run(main())
