# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generated Markdown outputs are not required bundled inputs."""

from pathlib import Path

import pytest

from skillspector.references import resolve_bundle_references_with_metadata


def resolve(root: Path, body: str, known: list[str] | None = None):
    (root / "SKILL.md").write_text(body, encoding="utf-8")
    return resolve_bundle_references_with_metadata(
        root,
        source_path="SKILL.md",
        source_text=body,
        known_paths=known or ["SKILL.md"],
    )


@pytest.mark.parametrize(
    "body",
    [
        "### Step 10\n\n5. Write `authz-coverage-report.md` to the working directory.\n",
        "### Step 5 - Write report\n\nFile `cache-effectiveness-report.md` in current working directory:\n",
        "### Step 5 - Write report\n\nReport structure (Markdown), file "
        "`spec-check-report.md` in the current working directory:\n",
        "- `/stackcompass save` - after analysis, save report to `stackcompass-report.md`\n",
    ],
)
def test_explicit_generated_report_has_no_missing_file(tmp_path: Path, body: str) -> None:
    result = resolve(tmp_path, body)
    assert result.complete is True
    assert not [item for item in result.records if item["status"] == "missing"]


@pytest.mark.parametrize(
    "body",
    [
        "### Required files\n\nFile `config.md` in current working directory:\n",
        "### Step 5 - Read report\n\nFile `config.md` in current working directory:\n",
        "### Step 5 - Write report\n\nRead `config.md` from working directory.\n",
        "5. Write `run.sh` to the working directory.\n",
        "5. Write `scripts/report.md` to the working directory.\n",
        "5. Write `config.md` to the build directory.\n",
        "Do not save report to `secret.md`.\n",
        "Run `bash scripts/required.sh` before continuing.\n",
    ],
)
def test_unqualified_input_or_executable_stays_missing(tmp_path: Path, body: str) -> None:
    result = resolve(tmp_path, body)
    assert result.complete is True
    assert any(item["status"] == "missing" for item in result.records), result.records


def test_present_report_file_wins_over_output_metadata(tmp_path: Path) -> None:
    (tmp_path / "authz-coverage-report.md").write_text("# Existing file\n", encoding="utf-8")
    result = resolve(
        tmp_path,
        "5. Write `authz-coverage-report.md` to the working directory.\n",
        ["SKILL.md", "authz-coverage-report.md"],
    )
    assert result.complete
    assert any(
        row["status"] == "resolved" and row["target_path"] == "authz-coverage-report.md"
        for row in result.records
    )


def test_independent_input_not_suppressed_by_output_in_same_source(tmp_path: Path) -> None:
    body = (
        "5. Write `summary-report.md` to the working directory.\n"
        "Read `source-config.md` before producing the report.\n"
    )
    result = resolve(tmp_path, body)
    assert result.complete
    assert any(
        row["status"] == "missing" and "source-config.md" in row["evidence"]
        for row in result.records
    )
