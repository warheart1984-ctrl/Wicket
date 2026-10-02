"""Skip tests for parts of the original lawful-nova-shell that are not part of infinity-core.

Only the Python core (nova/, bin/, config/, policy.yaml) was brought over. The installers,
quickstart scripts, desktop app and packaging scripts were left out, so tests that read
those files cannot pass here. They are skipped by name (and show up as skips in every
run) instead of being deleted or edited.
"""

import pytest

# Whole files that only test the left-out installers, quickstart, desktop and packaging.
collect_ignore = [
    "tests/test_github_download_ready.py",
    "tests/test_unix_shell_support.py",
    "tests/test_windows_program_package.py",
]

# Individual tests in test_local_nova_shell.py that read left-out files or scripts.
LEFT_OUT = {
    "test_parent_stack_launchers_prefer_lawful_nova_package",
    "test_productization_gate_checks_chain_contract",
    "test_deepseek_coding_substrate_files_and_profiles_are_wired",
    "test_configure_coding_substrate_writes_registry_and_codex_config",
}


def pytest_collection_modifyitems(config, items):
    skip = pytest.mark.skip(reason="tests a part of lawful-nova-shell not brought into infinity-core")
    for item in items:
        if item.name in LEFT_OUT:
            item.add_marker(skip)
