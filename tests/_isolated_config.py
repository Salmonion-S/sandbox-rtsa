import os
import tempfile
from contextlib import contextmanager

import yaml

from config.manager import ConfigManager


@contextmanager
def isolated_config_dir():
    with tempfile.TemporaryDirectory(prefix="rtsa_test_config_") as tmpdir:
        yield tmpdir


def build_isolated_config(tmpdir, config_dict):
    merged = dict(config_dict)
    database_section = dict(merged.get("database") or {})
    database_section.setdefault("path", os.path.join(tmpdir, "data", "rtsa.db"))
    merged["database"] = database_section
    config_path = os.path.join(tmpdir, "config.yaml")
    with open(config_path, "w") as f:
        yaml.safe_dump(merged, f)
    return ConfigManager(config_path)


@contextmanager
def isolated_config_manager(config_dict):
    with isolated_config_dir() as tmpdir:
        yield build_isolated_config(tmpdir, config_dict)
