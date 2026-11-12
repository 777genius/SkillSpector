# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bounded directory-link resolution must not hide missing executable files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillspector.cli import app
from skillspector.references import resolve_bundle_references_with_metadata


@pytest.mark.parametrize(
    ("source_path", "source", "known", "expected"),
    [
        ("SKILL.md", "See [components](./components/).",
         ["SKILL.md", "components/accordion.md", "components/forms/button.md"], "components"),
        ("docs/SKILL.md", "See [components](../components/).",
         ["docs/SKILL.md", "components/accordion.md"], "components"),
    ],
)
def test_explicit_markdown_directory_link_uses_only_bounded_known_descendants(
    tmp_path: Path, source_path: str, source: str, known: list[str], expected: str
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path=source_path, source_text=source, known_paths=known
    )
    assert result.complete is True
    assert len(result.records) == 1
    assert result.records[0]["status"] == "uninspected"
    assert result.records[0]["target_path"] == expected
    assert result.records[0]["disposition"] == "partial"
    assert result.records[0]["reference_kind"] == "markdown_link"


@pytest.mark.parametrize(
    ("source", "known", "expected"),
    [
        ("See [components](components/%2F).",
         ["SKILL.md", "components/accordion.md"], "missing"),
        ("See [components](./components/).",
         ["SKILL.md", "components-extra/accordion.md"], "missing"),
        ("See [components](./components/).",
         ["SKILL.md"], "missing"),
        ("See [missing](./scripts/).",
         ["SKILL.md", "components/accordion.md"], "missing"),
        ("See [outside](../outside/).",
         ["SKILL.md", "components/accordion.md"], "rejected"),
        ("Run `python3 scripts/emit.py`.",
         ["SKILL.md", "scripts/docs/guide.md"], "missing"),
    ],
)
def test_directory_resolution_keeps_missing_and_escape_cases(
    tmp_path: Path, source: str, known: list[str], expected: str
) -> None:
    # Files created on disk are deliberately not in the admitted inventory.
    # The resolver must never probe them or infer unobserved contents.
    (tmp_path / "components").mkdir()
    (tmp_path / "components" / "secret.txt").write_text("outside admitted inventory")
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=source, known_paths=known
    )
    assert result.complete is True
    assert result.records
    assert expected in {r["status"] for r in result.records}
    assert all(r["status"] != "resolved" for r in result.records)


@pytest.mark.parametrize(
    "source",
    [
        "Read `components/`.",
        "See ![image](components/).",
        "```markdown\n[components](components/)\n```",
    ],
)
def test_only_real_markdown_navigation_can_resolve_a_directory(
    tmp_path: Path, source: str
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=source,
        known_paths=["SKILL.md", "components/accordion.md"]
    )
    assert result.complete
    assert all(r["status"] != "resolved" for r in result.records)


def test_cli_directory_link_is_resolved_but_real_missing_script_remains_partial(
    tmp_path: Path,
) -> None:
    (tmp_path / "components").mkdir()
    (tmp_path / "components" / "accordion.md").write_text("# Accordion\n", encoding="utf-8")
    (tmp_path / "SKILL.md").write_text(
        "---\nname: directory-navigation\ndescription: Read bundled component docs.\n---\n"
        "# Components\n\nSee [component docs](./components/).\n"
        "Run `python3 scripts/missing.py` to produce the report.\n",
        encoding="utf-8",
    )
    run = CliRunner().invoke(
        app, ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    )
    assert run.exit_code == 1, run.output
    result = json.loads(run.stdout)
    references = result["analysis_completeness"]["references"]
    assert any(
        r["status"] == "uninspected" and r["target_path"] == "components"
        and r["disposition"] == "partial"
        and r["reference_kind"] == "markdown_link"
        for r in references
    )
    assert any(
        r["status"] == "missing" and r["disposition"] == "partial"
        and r["target_path"] is None
        for r in references
    )
    assert "referenced_uninspected" in {
        e["reason_code"] for e in result["analysis_completeness"]["ledger_exceptions"]
    }
    assert result["analysis_completeness"]["is_complete"] is False
