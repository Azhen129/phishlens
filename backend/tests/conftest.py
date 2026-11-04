"""Legacy rule tests are independent of locally installed production models."""
import pytest

from backend import ml_runtime


def pytest_configure(config):
    config.addinivalue_line("markers", "real_models: read-only smoke test of the checked local trained artifacts")


@pytest.fixture(autouse=True)
def isolate_default_models(request, tmp_path, monkeypatch):
    if request.node.get_closest_marker("real_models"):
        yield
        return
    monkeypatch.setattr(ml_runtime, "MODEL_ROOT", tmp_path / "absent-models")
    ml_runtime.clear_cache()
    yield
    ml_runtime.clear_cache()
