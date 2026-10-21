"""Regression for fix-version-drift-package-metadata (v0.9.0).

The v0.8.0 release bumped only the ``VERSION`` file and left every Python
package-version surface one release behind: ``canaryprobe.__version__`` and
``pyproject.toml``'s ``version`` both read ``0.7.0`` at the ``v0.8.0`` tag, so
``canaryprobe --version`` reported ``0.7.0`` and a wheel built from that tag
was named ``canaryprobe-0.7.0`` — colliding with the previously-shipped
``v0.7.0`` wheel and making the ``v0.8.0`` release un-installable as
``0.8.0``.

This pins the three version-reporting surfaces together so a future release
that bumps only one of them (the exact regression that shipped v0.8.0) re-opens
the drift loudly here in CI instead of shipping a mis-versioned distribution.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import canaryprobe

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_VERSION_FILE = _REPO_ROOT / "VERSION"
_SITE_JSON = _REPO_ROOT / "web" / "site.json"


def _pyproject_version() -> str:
    with _PYPROJECT.open("rb") as fh:
        data = tomllib.load(fh)
    return data["project"]["version"]


def _version_file_value() -> str:
    """The bare form (the ``VERSION`` file stores a leading ``v``)."""
    return _VERSION_FILE.read_text(encoding="utf-8").strip().lstrip("v")


def _site_json() -> dict:
    return json.loads(_SITE_JSON.read_text(encoding="utf-8"))


def test_init_version_matches_pyproject():
    """``canaryprobe.__version__`` must equal the ``pyproject.toml`` version.

    At v0.8.0 these disagreed by a full release (``0.7.0`` vs ``v0.8.0``); a
    wheel built from the tag then carried the wrong version metadata.
    """
    assert canaryprobe.__version__ == _pyproject_version()


def test_version_file_matches_pyproject():
    """The ``VERSION`` file (bare form) must equal the ``pyproject.toml``
    version. The two are separate surfaces that must move in lockstep."""
    assert _version_file_value() == _pyproject_version()


def test_all_version_surfaces_equal_target():
    """Every version-reporting surface resolves to the same release."""
    expected = canaryprobe.__version__
    assert _pyproject_version() == expected
    assert _version_file_value() == expected


def test_cli_version_flag_reports_true_release():
    """``canaryprobe --version`` must print the package version, not a stale
    value. Drives the Typer app so the flag path (``cli._version_callback``)
    is covered, not just the import."""
    from typer.testing import CliRunner

    from canaryprobe.cli import app

    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert canaryprobe.__version__ in (result.stdout or "")


def test_site_json_content_version_matches_release():
    """Regression for quality-version-lockstep-pin-site-json (v0.10.0).

    The v0.9.0 fix (fix-version-drift-package-metadata) claims four version
    surfaces move in lockstep — including web/site.json's ``content_version`` —
    but pinned only three. This closes the gap: the site is the most public
    surface (canaryprobe.lei6393.com), so a release that bumps the code
    surfaces but leaves the site stale re-opens the drift loudly here.
    """
    expected = canaryprobe.__version__
    site = _site_json()
    assert site["content_version"].lstrip("v") == expected
    assert site["meta"]["content_version"].lstrip("v") == expected


def test_site_json_changelog_latest_matches_release():
    """The site's latest changelog entry must describe the shipping release."""
    expected = canaryprobe.__version__
    site = _site_json()
    assert site["changelog"], "site.json must carry a changelog"
    assert site["changelog"][0]["version"].lstrip("v") == expected


def test_readme_version_lines_match_release():
    """Both READMEs quote the release on their version line; a release that bumps
    the code surfaces and leaves a README stale would advertise the wrong version
    on the two pages a visitor reads first."""
    expected = canaryprobe.__version__
    for name in ("README.md", "README.en.md"):
        text = (_REPO_ROOT / name).read_text(encoding="utf-8")
        assert f"`v{expected}`" in text, f"{name} does not quote v{expected}"


def test_changelog_latest_entry_matches_release():
    """``CHANGELOG.md`` must carry an entry for the shipping release — a release
    with no changelog entry leaves its own changes undocumented."""
    expected = canaryprobe.__version__
    text = (_REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{expected}]" in text, f"CHANGELOG.md has no [{expected}] entry"

