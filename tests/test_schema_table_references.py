# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Treat only verified typed Markdown API properties as scalar documentation."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillspector.cli import app
from skillspector.references import resolve_bundle_references_with_metadata


HEADER = "| Field | Type | Description |\n|-------|------|-------------|\n"


def resolve(root: Path, body: str, files: list[str] | None = None):
    return resolve_bundle_references_with_metadata(
        root, source_path="SKILL.md", source_text=body,
        known_paths=["SKILL.md", *(files or [])],
    )


@pytest.mark.parametrize(
    ("field", "kind", "description"),
    [
        ("data.id", "uuid", "Identifies the type of resource."),
        ("data.payload.call_duration_secs", "integer", "The duration of the call."),
        ("data.payload.connection_id", "string", "The connection identifier."),
        ("data.event_type", "enum: fax.delivered", "The event being delivered."),
        ("meta.delivered_to", "uri", "The webhook URL."),
    ],
)
def test_realistic_typed_webhook_fields_are_not_missing(
    tmp_path: Path, field: str, kind: str, description: str,
) -> None:
    body = "### Webhook payload fields\n\n" + HEADER
    body += f"| `{field}` | {kind} | {description} |\n"
    result = resolve(tmp_path, body)
    assert result.complete
    assert result.raw_candidates_considered == 1
    assert result.accepted_references == 0
    assert result.records == []


def test_multiple_documented_field_rows_keep_other_true_missing_references(tmp_path: Path) -> None:
    body = "### Webhook payload fields\n\n" + HEADER
    body += "| `data.id` | uuid | Identifies the type of resource. |\n"
    body += "| `data.payload.from` | string | Calling phone number. |\n"
    body += "| `scripts/run.sh` | string | Execute the local script. |\n"
    result = resolve(tmp_path, body)
    assert result.complete
    assert not any("data.id" in row["evidence"] for row in result.records)
    assert not any("data.payload.from" in row["evidence"] for row in result.records)
    assert any(row["status"] == "missing" and "scripts/run.sh" in row["evidence"]
               for row in result.records)


@pytest.mark.parametrize(
    "body",
    [
        "| `data.id` | uuid | An identifier. |",
        "| Field | Value | Description |\n|-------|------|-------------|\n"
        "| `data.id` | uuid | An identifier. |",
        HEADER + "| `data.id` | binary | Read from a file. |",
        HEADER + "| `data.id` | enum: ../../outside | A value. |",
        HEADER + "| `data.id` | uuid | Path to the missing file. |",
        HEADER + "| `config.json` | string | Setting. |",
        HEADER + "| `data.id` | uuid | A property. | extra |",
        "```markdown\n" + HEADER + "| `data.id` | uuid | An identifier. |\n```",
        HEADER + "| `data.id` | uuid | An identifier. |\n\n"
        "| `data.payload.to` | string | Phone number. |",
    ],
)
def test_unverified_schema_context_never_hides_missing_reference(
    tmp_path: Path, body: str,
) -> None:
    result = resolve(tmp_path, body)
    assert result.complete
    assert any(row["status"] == "missing" for row in result.records)


def test_real_inventory_wins_over_schema_exemption(tmp_path: Path) -> None:
    result = resolve(
        tmp_path, HEADER + "| `data.id` | uuid | An identifier. |",
        ["data.id"],
    )
    assert result.complete
    assert len(result.records) == 1
    assert result.records[0]["status"] == "resolved"
    assert result.records[0]["target_path"] == "data.id"


def test_real_no_llm_cli_verifies_typed_webhook_field_and_missing_script(tmp_path: Path) -> None:
    skill = tmp_path / "SKILL.md"
    skill.write_text(
        "---\nname: schema-table-proof\ndescription: Documents an API payload.\n---\n"
        "### Webhook payload fields\n\n" + HEADER
        + "| `data.id` | uuid | Identifies the resource. |\n"
        + "| `data.event_type` | enum: delivered | The type of event. |\n",
        encoding="utf-8",
    )
    ok = CliRunner().invoke(
        app, ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"],
    )
    assert ok.exit_code == 0, ok.output
    report = json.loads(ok.stdout)
    assert report["execution_successful"] is True
    assert not any("data.id" in row["evidence"] for row in
                   report["analysis_completeness"]["references"])

    skill.write_text(skill.read_text() + "\nRun `bash scripts/setup.sh`.\n", encoding="utf-8")
    partial = CliRunner().invoke(
        app, ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"],
    )
    assert partial.exit_code in (0, 1), partial.output
    incomplete = json.loads(partial.stdout)
    assert any(row["status"] == "missing" and "scripts/setup.sh" in row["evidence"]
               for row in incomplete["analysis_completeness"]["references"])
