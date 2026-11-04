import pytest

from globalban.config import load_config


def test_config_rejects_string_boolean(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("actions:\n  dry_run: 'false'\n", encoding="utf-8")

    with pytest.raises(ValueError, match="actions.dry_run must be a boolean"):
        load_config(path)