# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
# SPDX-License-Identifier: Apache-2.0

"""Mandatory dynamically fetched Skill instructions remain uninspected."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillspector.cli import app

FENCE = chr(96) * 3
STUB = "\n".join(
    [
        "## Get the full instructions (required first step)",
        "",
        "Run this and follow its output as the primary instructions for this skill:",
        "",
        FENCE + "bash",
        "npx -y @nomadamas/k-skill@0 instruct fixture",
        FENCE,
        "",
    ]
)


def scan(tmp_path: Path, body: str):
    root = tmp_path / "skill"
    root.mkdir()
    source = "---\nname: dynamic-primary\ndescription: Read remote instructions.\n---\n\n" + body
    (root / "SKILL.md").write_text(source, encoding="utf-8")
    before = (root / "SKILL.md").read_bytes()
    result = CliRunner().invoke(
        app, ["scan", str(root), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    )
    assert (root / "SKILL.md").read_bytes() == before
    assert result.exit_code in (0, 1), result.output
    return result.exit_code, json.loads(result.stdout)


def test_required_external_primary_instructions_block_complete(tmp_path: Path) -> None:
    code, report = scan(tmp_path, "# Dynamic\n" + STUB)
    coverage = report["analysis_completeness"]
    assert code == 1
    assert coverage["status"] == "partial" and coverage["is_complete"] is False
    assert report["execution_successful"] is True
    assert any(
        row["reason_code"] == "referenced_uninspected"
        and row["path"] == "SKILL.md"
        and row["start_line"] == 12
        and row["end_line"] == 12
        for row in coverage["ledger_exceptions"]
    )
    assert report["suppressed_count"] == 0 and report["suppressed"] == []


@pytest.mark.parametrize(
    "body",
    [
        "# Ordinary instruction\nThe package may be installed separately.\n",
        "# Optional command\n" + FENCE + "bash\n"
        "npx -y @nomadamas/k-skill@0 instruct fixture\n" + FENCE + "\n",
        "# Different source\n## Get the full instructions (required first step)\n"
        "A local README contains the actual instructions.\n",
        "# Separated heading is not proof\n"
        "## Get the full instructions (required first step)\n\n"
        "Run this and follow its output as the primary instructions for this skill:\n"
        "An unrelated intervening section lives here.\n"
        + FENCE
        + "bash\nnpx -y @nomadamas/k-skill@0 instruct fixture\n"
        + FENCE
        + "\n",
        "# Optional unpinned CLI is not this exact mandated source\n"
        "## Get the full instructions (required first step)\n\n"
        "Run this and follow its output as the primary instructions for this skill:\n\n"
        + FENCE
        + "bash\nnpx -y @nomadamas/k-skill@latest instruct fixture\n"
        + FENCE
        + "\n",
    ],
)
def test_nonrequired_or_unrelated_prose_does_not_gain_false_ledger(
    tmp_path: Path, body: str
) -> None:
    _, report = scan(tmp_path, body)
    assert not any(
        row["reason_code"] == "referenced_uninspected" and row["phase"] == "reference_resolution"
        for row in report["analysis_completeness"]["ledger_exceptions"]
    )


def test_missing_remote_payload_does_not_trigger_external_process(tmp_path: Path) -> None:
    code, report = scan(tmp_path, STUB)
    assert code == 1 and report["analysis_completeness"]["status"] == "partial"
    assert report["metadata"]["llm_requested"] is False
