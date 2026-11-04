# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reject escaping local references without declaring their contents inspected."""

import builtins
import io
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from skillspector.cli import app
from skillspector.references import resolve_bundle_references_with_metadata


@pytest.mark.parametrize(
    "destination",
    [
        "../outside-runner.sh",
        "%2e%2e/outside-runner.sh",
        "..%2Foutside-runner.sh",
        "..%5Coutside-runner.sh",
        "../../outside-runner.sh",
        "%2Foutside-runner.sh",
        "%5Coutside-runner.sh",
        "C%3A/outside-runner.sh",
        "C:/outside-runner.sh",
        "C:../outside-runner.sh",
        "file:///outside-runner.sh",
        "file://localhost/outside-runner.sh",
    ],
)
def test_escaping_markdown_reference_is_uninspected(
    tmp_path: Path, destination: str
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=f"Run [the outside script]({destination}) to produce a report.",
        known_paths=["SKILL.md"],
    )
    assert result.complete
    assert len(result.records) == 1
    assert result.records[0]["status"] == "rejected"
    assert result.records[0]["disposition"] == "partial"
    assert result.records[0]["target_path"] is None


@pytest.mark.parametrize("destination", ["https://example.invalid/docs.md", "#documentation"])
def test_external_documentation_is_not_local_dependency(
    tmp_path: Path, destination: str
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=f"Read [documentation]({destination}).",
        known_paths=["SKILL.md"],
    )
    assert result.complete
    assert all(item["disposition"] == "out_of_scope" for item in result.records)


def test_parent_navigation_within_bundle_keeps_normal_resolution(tmp_path: Path) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="nested/SKILL.md",
        source_text="Read [guide](../docs/guide.md).",
        known_paths=["nested/SKILL.md", "docs/guide.md"],
    )
    assert result.complete
    assert len(result.records) == 1
    assert result.records[0]["status"] == "resolved"
    assert result.records[0]["target_path"] == "docs/guide.md"


@pytest.mark.parametrize(
    "instruction",
    [
        "Run [the outside script](../outside-runner.sh) to produce a report.\n",
        "Run `python3 ../outside-runner.sh` to produce a report.\n",
        "Run `python3 -u ../outside-runner.sh` to produce a report.\n",
        "Run [the outside script]({outside_uri}) to produce a report.\n",
    ],
)
def test_cli_parent_escape_never_reports_complete(
    tmp_path: Path, instruction: str
) -> None:
    outside = tmp_path / "outside-runner.sh"
    outside.write_text("# This file must never be executed or read by the scan.\n", encoding="utf-8")
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: escaping-reference\ndescription: Inspect a script dependency.\n---\n"
        + instruction.format(outside_uri=outside.as_uri()),
        encoding="utf-8",
    )
    before = outside.read_bytes()

    def forbid_outside_file_open(original):
        def checked(path, *args, **kwargs):
            # Inspect basename as well as absolute paths: os.open may receive
            # an fd-relative filename when the caller uses dir_fd.
            if isinstance(path, (str, bytes, os.PathLike)) and (
                os.path.basename(os.fsdecode(path)) == outside.name
            ):
                raise AssertionError("Scanner opened a file outside its acquired Skill")
            return original(path, *args, **kwargs)
        return checked

    with (
        patch("builtins.open", side_effect=forbid_outside_file_open(builtins.open)),
        patch("io.open", side_effect=forbid_outside_file_open(io.open)),
        patch("os.open", side_effect=forbid_outside_file_open(os.open)),
    ):
        run = CliRunner().invoke(
            app, ["scan", str(skill), "--no-llm", "--format", "json", "--fail-on-incomplete"]
        )
    assert run.exit_code == 1, run.output
    report = json.loads(run.stdout)
    coverage = report["analysis_completeness"]
    assert report["execution_successful"] is True
    assert coverage["is_complete"] is False
    assert coverage["status"] == "partial"
    assert any(
        r["status"] == "rejected" and r["disposition"] == "partial"
        for r in coverage["references"]
    )
    assert any(
        event["reason_code"] == "referenced_uninspected"
        for event in coverage["ledger_exceptions"]
    )
    assert outside.read_bytes() == before


@pytest.mark.parametrize("body", [
    "Run `python3 ../outside-runner.sh` now.",
    "Run `python3 -u ../outside-runner.sh` now.",
    "Run `bash -- ../outside-runner.sh` now.",
])
def test_escaping_inline_command_is_uninspected(tmp_path: Path, body: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=body,
        known_paths=["SKILL.md"],
    )
    assert result.complete
    assert any(
        item["reference_kind"] == "inline_command"
        and item["status"] == "rejected"
        and item["disposition"] == "partial"
        for item in result.records
    )


def test_true_missing_command_remains_incomplete(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: true-missing-script\ndescription: Check script dependency.\n---\n"
        "Run `python3 scripts/emit.py` to produce a report.\n",
        encoding="utf-8",
    )
    run = CliRunner().invoke(
        app, ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    )
    assert run.exit_code == 1, run.output
    report = json.loads(run.stdout)
    coverage = report["analysis_completeness"]
    assert coverage["is_complete"] is False
    assert any(r["status"] == "missing" for r in coverage["references"])
    assert any(
        event["reason_code"] == "reference_missing"
        for event in coverage["ledger_exceptions"]
    )
