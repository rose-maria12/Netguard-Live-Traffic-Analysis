import pytest


@pytest.fixture(autouse=True)
def _isolate_models_dir(tmp_path, monkeypatch):
    """
    Redirect NETGUARD_MODELS_DIR to an isolated per-test directory so unit tests
    never pollute data/models/ or inadvertently load production artifacts when
    running against temporary databases.
    """
    models_dir = tmp_path / "isolated_models"
    models_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NETGUARD_MODELS_DIR", str(models_dir))

    caps_dir = tmp_path / "isolated_captures"
    caps_dir.mkdir(parents=True, exist_ok=True)
    import netguard.pipeline as pipeline_mod
    monkeypatch.setattr(pipeline_mod, "CAPTURES_DIR", caps_dir)


