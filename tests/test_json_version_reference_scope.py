# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Narrow source-bound JSON VERSION literals; preserve actual file dependencies."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillspector.cli import app
from skillspector.references import resolve_bundle_references_with_metadata


@pytest.mark.parametrize(
    "source",
    [
        '"VERSION": "1.0.0",\n',
        '   "VERSION" : "25.17.2"  \n',
        '\x60\x60\x60json\n{\n  "VERSION": "1.0.0",\n}\n\x60\x60\x60\n',
    ],
)
def test_strict_json_version_is_only_metadata(tmp_path: Path, source: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=source, known_paths=["SKILL.md"]
    )
    assert result.complete is True
    assert result.records == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('"version": "1.0.0",\n', "missing"),
        ('"VERSION": "1.x",\n', "missing"),
        ('"VERSION": "0.0.0.0",\n', "missing"),
        ('"VERSION": "1.0.0", "file": "missing.md"\n', "missing"),
        ('\x60data.coverage\x60\n', "missing"),
        ('[VERSION file](1.0.0)\n', "missing"),
        ('Read [missing.md](missing.md)\n', "missing"),
        ('Run \x60python3 scripts/required.sh\x60.\n', "missing"),
        ('Use \x60runtime/generated.json\x60.\n', "missing"),
        ('[outside](../outside.md)\n', "rejected"),
    ],
)
def test_other_version_shapes_and_real_dependencies_are_not_exempt(
    tmp_path: Path, source: str, expected: str
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=source, known_paths=["SKILL.md"]
    )
    assert result.complete is True
    assert result.records, source
    assert expected in {item["status"] for item in result.records}, result.records


def test_numeric_filename_markdown_link_still_resolves(tmp_path: Path) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text="Read [actual file](1.0.0).",
        known_paths=["SKILL.md", "1.0.0"],
    )
    assert result.complete is True
    assert any(
        entry["status"] == "resolved" and entry["target_path"] == "1.0.0"
        for entry in result.records
    )


def _write_skill(tmp_path: Path, body: str) -> Path:
    root = tmp_path / "skill"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: json-version-contract\ndescription: Verify JSON metadata.\n---\n"
        + body,
        encoding="utf-8",
    )
    return root


def test_real_no_llm_cli_only_version_completes(tmp_path: Path) -> None:
    root = _write_skill(tmp_path, '\x60\x60\x60json\n{\n"VERSION": "1.0.0"\n}\n\x60\x60\x60\n')
    original = (root / "SKILL.md").read_bytes()
    result = CliRunner().invoke(
        app, ["scan", str(root), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    coverage = report["analysis_completeness"]
    assert report["execution_successful"] is True
    assert coverage["status"] == "complete" and coverage["is_complete"] is True
    assert not [r for r in coverage["references"] if "1.0.0" in r["evidence"]]
    assert (root / "SKILL.md").read_bytes() == original


def test_real_no_llm_cli_missing_executable_remains_incomplete(tmp_path: Path) -> None:
    root = _write_skill(
        tmp_path, '\x60\x60\x60json\n{\n"VERSION": "1.0.0"\n}\n\x60\x60\x60\n'
        "Run \x60python3 scripts/required.sh\x60 before continuing.\n"
    )
    original = (root / "SKILL.md").read_bytes()
    result = CliRunner().invoke(
        app, ["scan", str(root), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    )
    assert result.exit_code == 1, result.output
    report = json.loads(result.stdout)
    coverage = report["analysis_completeness"]
    assert coverage["is_complete"] is False
    assert any(
        ref["status"] == "missing" and "scripts/required.sh" in ref["evidence"]
        for ref in coverage["references"]
    )
    assert not any("1.0.0" in ref["evidence"] for ref in coverage["references"])
    assert (root / "SKILL.md").read_bytes() == original


def test_missing_interpreter_operand_alone_cannot_be_complete_with_caveats(
    tmp_path: Path,
) -> None:
    """A missing executable is not equivalent to a passive unbundled document."""
    root = _write_skill(tmp_path, "Run `python3 scripts/required.sh` before continuing.\n")
    before = (root / "SKILL.md").read_bytes()
    result = CliRunner().invoke(
        app, ["scan", str(root), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    )
    assert result.exit_code == 1, result.output
    report = json.loads(result.stdout)
    completeness = report["analysis_completeness"]
    assert completeness["status"] == "partial"
    assert completeness["is_complete"] is False
    assert any(
        ref["reference_kind"] == "inline_command"
        and ref["status"] == "missing"
        and ref["target_path"] is None
        for ref in completeness["references"]
    )
    assert any(
        row.get("reason_code") == "referenced_uninspected"
        for row in completeness["ledger_exceptions"]
    )
    assert (root / "SKILL.md").read_bytes() == before
