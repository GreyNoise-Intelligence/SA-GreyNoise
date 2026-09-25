"""Pytest fixtures and Splunk-platform stubs for running app tests outside Splunk."""

import logging
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "APP_FILES_ONLY" / "SA-GreyNoise"
APP_BIN = APP_DIR / "bin"
VENDOR_LIB = APP_BIN / "SA_GreyNoise"

for path in (str(APP_BIN), str(VENDOR_LIB)):
    if path not in sys.path:
        sys.path.insert(0, path)


def _install_splunk_stubs():
    """Provide the Splunk Python modules that exist only on Splunk hosts."""
    if "splunk" in sys.modules and hasattr(sys.modules["splunk"], "rest"):
        return

    splunk = types.ModuleType("splunk")
    rest = types.ModuleType("splunk.rest")
    rest.simpleRequest = MagicMock(return_value=(MagicMock(), b"{}"))

    clilib = types.ModuleType("splunk.clilib")
    bundle_paths = types.ModuleType("splunk.clilib.bundle_paths")
    bundle_paths.make_splunkhome_path = lambda parts: str(Path("/tmp").joinpath(*parts))
    cli_common = types.ModuleType("splunk.clilib.cli_common")
    cli_common.getMgmtUri = lambda: "https://127.0.0.1:8089"

    admin = types.ModuleType("splunk.admin")

    class MConfigHandler:
        def getSessionKey(self):
            return "test-session-key"

    admin.MConfigHandler = MConfigHandler

    splunk.rest = rest
    splunk.clilib = clilib
    splunk.admin = admin

    sys.modules["splunk"] = splunk
    sys.modules["splunk.rest"] = rest
    sys.modules["splunk.clilib"] = clilib
    sys.modules["splunk.clilib.bundle_paths"] = bundle_paths
    sys.modules["splunk.clilib.cli_common"] = cli_common
    sys.modules["splunk.admin"] = admin


_install_splunk_stubs()


@pytest.fixture(scope="session")
def app_dir():
    return APP_DIR


@pytest.fixture(scope="session")
def app_bin():
    return APP_BIN


@pytest.fixture
def logger():
    test_logger = logging.getLogger("sa_greynoise_tests")
    test_logger.handlers = []
    test_logger.addHandler(logging.NullHandler())
    test_logger.propagate = False
    test_logger.setLevel(logging.DEBUG)
    return test_logger


@pytest.fixture(autouse=True)
def _stub_runtime_side_effects(monkeypatch, logger):
    """Keep command code off Splunk logging paths and KV cache during unit tests."""
    monkeypatch.setattr("utility.setup_logger", lambda **kwargs: logger, raising=False)
    monkeypatch.setattr("utility.get_caching", lambda *args, **kwargs: (0, None), raising=False)
    monkeypatch.setattr("utility.get_api_key", lambda *args, **kwargs: "test-api-key", raising=False)
    monkeypatch.setattr("utility.get_proxy", lambda *args, **kwargs: "", raising=False)
    monkeypatch.setattr("utility.validate_api_key", lambda *args, **kwargs: (True, "API key is valid"), raising=False)


@pytest.fixture
def command_metadata():
    searchinfo = SimpleNamespace(session_key="test-session-key", command="testcmd")
    return SimpleNamespace(searchinfo=searchinfo, preview=False)


@pytest.fixture
def ready_eventing_command(command_metadata):
    """Attach Splunk search-command metadata used by transforming commands."""

    def _prepare(command):
        command._metadata = command_metadata
        command._search_results_info = SimpleNamespace()
        command.write_error = MagicMock()
        command.write_warning = MagicMock()
        command.api_validation_flag = True
        command.api_key = "test-api-key"
        command.proxy = ""
        return command

    return _prepare
