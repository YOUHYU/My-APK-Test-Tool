"""The worker policy file is what stops a worker from launching arbitrary tools."""
from __future__ import annotations

import pytest

from apkplat import toolchain


def test_policy_file_is_loaded():
    rules = toolchain.policy(refresh=True)
    assert rules["policy_loaded"] is True, rules["policy_error"]
    assert rules["policy_error"] is None
    assert rules["policy_path"].endswith("worker-policy.yml")
    assert "java.exe" in [name.lower() for name in rules["allowed_executables"]]
    assert int(rules["max_timeout_seconds"]) == 900


def test_check_executable_rejects_anything_not_listed():
    toolchain.check_executable(["java.exe", "-version"])
    for disallowed in ("cmd.exe", "powershell.exe", "curl.exe", "python.exe"):
        with pytest.raises(toolchain.ToolError) as caught:
            toolchain.check_executable([disallowed])
        assert caught.value.code == "tool_not_allowed"
        assert disallowed in caught.value.message


def test_run_refuses_a_disallowed_executable_before_spawning(tmp_path):
    out = tmp_path / "out.log"
    err = tmp_path / "err.log"
    with pytest.raises(toolchain.ToolError) as caught:
        toolchain.run(
            ["cmd.exe", "/c", "echo", "should-not-run"],
            cwd=tmp_path,
            stdout_path=out,
            stderr_path=err,
            timeout=5,
        )
    assert caught.value.code == "tool_not_allowed"
    assert not out.exists() and not err.exists()


def test_child_env_drops_secret_shaped_extras():
    env = toolchain.child_env(
        {
            "APKPLAT_MODEL_API_KEY": "sk-should-not-leak",
            "GITHUB_TOKEN": "ghp_should_not_leak",
            "DSH_HOME": "C:/Users/x/.dsh",
            "HARMLESS_SETTING": "kept",
        }
    )
    assert env["HARMLESS_SETTING"] == "kept"
    for dropped in ("APKPLAT_MODEL_API_KEY", "GITHUB_TOKEN", "DSH_HOME"):
        assert dropped not in env
    assert "JAVA_HOME" in env and "PATH" in env
    assert "jdk" in env["JAVA_HOME"]


def test_official_tools_resolve():
    paths = toolchain.paths()
    rules = toolchain.policy()
    allowed = {name.lower() for name in rules["allowed_executables"]}
    for key in ("java", "aapt2", "adb", "node"):
        name = paths[key].name.lower()
        assert name in allowed, f"{key} ({name}) is not permitted by the policy"
