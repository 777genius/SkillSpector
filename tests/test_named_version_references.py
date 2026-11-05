# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Version-suffixed YAML metadata must not fabricate missing local files."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillspector.cli import app
from skillspector.references import resolve_bundle_references_with_metadata


@pytest.mark.parametrize(
    "key",
    [
        "methodology-version",
        "candor-package-version",
        "skill-library-version",
        '"methodology-version"',
        "'methodology-version'",
    ],
)
def test_named_version_frontmatter_is_metadata(tmp_path: Path, key: str) -> None:
    text = f'---\nname: example\nmetadata:\n  {key}: "3.1.0"\n---\n'
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=text, known_paths=["SKILL.md"]
    )
    assert result.complete
    assert result.records == []


@pytest.mark.parametrize(
    "text",
    [
        '---\nmetadata:\n  other-key: "3.1.0"\n---\n',
        '---\nmetadata:\n  methodology-version: "1.x"\n---\n',
        '---\nmetadata:\n  methodology-version: "docs/tool.1"\n---\n',
        '---\nname: example\n---\nmethodology-version: "3.1.0"\n',
        '---\nname: "example"\ndescription: |\n  methodology-version: "3.1.0"\n---\n',
    ],
)
def test_named_version_does_not_hide_other_references(tmp_path: Path, text: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=text, known_paths=["SKILL.md"]
    )
    assert result.complete
    assert any(item["status"] == "missing" for item in result.records)


@pytest.mark.parametrize("present", [False, True])
def test_named_version_preserves_explicit_numeric_file_reference(
    tmp_path: Path, present: bool
) -> None:
    text = '---\nmetadata:\n  methodology-version: "3.1.0"\n---\n'
    text += "Read [versioned artifact](3.1.0).\n"
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=text,
        known_paths=["SKILL.md", "3.1.0"] if present else ["SKILL.md"],
    )
    assert result.complete
    assert len(result.records) == 1
    assert result.records[0]["status"] == ("resolved" if present else "missing")


def test_named_version_only_real_cli_is_complete(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: braids-risk\ndescription: Review risks.\nmetadata:\n"
        '  methodology-version: "3.1.0"\n---\nExplain the risk.\n',
        encoding="utf-8",
    )
    run = CliRunner().invoke(
        app,
        ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"],
    )
    assert run.exit_code == 0, run.output
    report = json.loads(run.stdout)
    coverage = report["analysis_completeness"]
    assert coverage["is_complete"] is True
    assert coverage["references"] == []


def test_named_version_cannot_hide_missing_executable_cli(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: missing-script\ndescription: Check dependencies.\nmetadata:\n"
        '  methodology-version: "3.1.0"\n---\n'
        "Run `python3 scripts/emit.py` to produce the result.\n",
        encoding="utf-8",
    )
    run = CliRunner().invoke(
        app,
        ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"],
    )
    assert run.exit_code == 1, run.output
    report = json.loads(run.stdout)
    coverage = report["analysis_completeness"]
    assert coverage["is_complete"] is False
    assert any(item["status"] == "missing" for item in coverage["references"])
