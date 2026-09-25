# GreyNoise Splunk app regression tests

These tests live at the repository root so they are not packaged with `APP_FILES_ONLY/SA-GreyNoise`.

They exercise custom command behavior, feed indicator mapping, and scan-deployment contracts without a live Splunk instance or GreyNoise API. External calls are mocked.

## Run

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r tests/requirements.txt
python -m pytest
```

Run a subset:

```bash
python -m pytest tests/test_custom_commands.py
python -m pytest tests/test_feeds.py tests/test_scan_deployment.py
```

Pytest also runs as a pre-commit hook when files under `tests/`, `pytest.ini`, or `APP_FILES_ONLY/SA-GreyNoise/{bin,default,README}/` change. Install hooks once with `pre-commit install`.
