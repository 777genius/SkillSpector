# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Source-bound API schema fields must not hide real bundle dependencies."""

import json
from pathlib import Path

from typer.testing import CliRunner

from skillspector.cli import app
from skillspector.references import resolve_bundle_references_with_metadata


HEADER = "| Field | Type | Description |\n|-------|------|-------------|\n"
FIELD_ROWS = (
    "| `data.id` | uuid | Resource identifier. |\n"
    "| `data.payload.status` | enum: delivered | Status of the fax. |\n"
    "| `meta.delivered_to` | uri | Webhook destination. |\n"
)


def resolve(tmp_path: Path, source: str, known: list[str] | None = None):
    return resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=source,
        known_paths=known or ["SKILL.md"],
    )


def test_documented_api_table_fields_not_bundled_files(tmp_path: Path) -> None:
    result = resolve(tmp_path, HEADER + FIELD_ROWS)
    assert result.complete is True
    assert result.records == []


def test_only_missing_property_is_exempt_not_a_real_inventory_file(tmp_path: Path) -> None:
    result = resolve(tmp_path, HEADER + FIELD_ROWS, ["SKILL.md", "data.id"])
    assert any(
        entry["status"] == "resolved" and entry["target_path"] == "data.id"
        for entry in result.records
    )
    assert not any(
        entry["status"] == "missing" and "data.payload.status" in entry["evidence"]
        for entry in result.records
    )


def test_unproven_schema_context_does_not_discard_missing_reference(tmp_path: Path) -> None:
    invalid = (
        "| File | Type | Description |\n|------|------|-------------|\n"
        "| `data.id` | uuid | Read from file. |\n",
        "| Field | Type | Description |\n"
        "| `data.id` | uuid | No delimiter. |\n",
        "| Field | Type | Description |\n|-------|------|-------------|\n"
        "| `data.id` | file | Real required file. |\n",
        "~~\n" + HEADER + FIELD_ROWS + "~~\n",
        "~~~markdown\n" + HEADER + FIELD_ROWS + "~~~\n",
        "| Field | Type | Description |\n|-------|------|-------------|\n"
        "| `data.id` | uuid | Field. |\n\n"
        "| `data.payload.status` | string | Outside the table. |\n",
    )
    for text in invalid:
        result = resolve(tmp_path, text)
        assert result.complete is True
        assert any(r["status"] == "missing" for r in result.records), text


def test_table_does_not_hide_independent_link_or_command(tmp_path: Path) -> None:
    result = resolve(
        tmp_path,
        HEADER + FIELD_ROWS
        + "Run `python3 scripts/required.sh` before continuing.\n"
        + "Read [bundle script](scripts/helper.py).\n",
    )
    missing = [row["evidence"] for row in result.records if row["status"] == "missing"]
    assert any("scripts/required.sh" in value for value in missing)
    assert any("scripts/helper.py" in value for value in missing)
    assert not any("data.payload.status" in value for value in missing)


def test_real_no_llm_cli_schema_only_complete_but_missing_script_partial(tmp_path: Path) -> None:
    root = tmp_path / "skill"
    root.mkdir()
    header = "---\nname: webhook-schema\ndescription: Document a webhook schema.\n---\n"
    path = root / "SKILL.md"
    path.write_text(header + "### Webhook payload fields\n\n" + HEADER + FIELD_ROWS)
    before = path.read_bytes()
    cli = CliRunner()
    clean = cli.invoke(app, ["scan", str(root), "--no-llm", "--format", "json", "--fail-on-incomplete"])
    assert clean.exit_code == 0, clean.output
    report = json.loads(clean.stdout)
    assert report["analysis_completeness"]["is_complete"] is True
    assert path.read_bytes() == before

    path.write_text(header + HEADER + FIELD_ROWS
                    + "Run `python3 scripts/required.sh` before continuing.\n")
    adverse = cli.invoke(app, ["scan", str(root), "--no-llm", "--format", "json", "--fail-on-incomplete"])
    assert adverse.exit_code == 1, adverse.output
    coverage = json.loads(adverse.stdout)["analysis_completeness"]
    assert coverage["status"] == "partial"
    assert coverage["is_complete"] is False
    assert any(
        row["status"] == "missing" and "scripts/required.sh" in row["evidence"]
        for row in coverage["references"]
    )
