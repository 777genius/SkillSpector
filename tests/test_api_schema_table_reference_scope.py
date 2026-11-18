# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Source-bound API schema fields must not hide real bundle dependencies."""

import json
from pathlib import Path

import pytest
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
        tmp_path,
        source_path="SKILL.md",
        source_text=source,
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


@pytest.mark.parametrize(
    "filename",
    [
        "scripts.required.sh",
        "config.settings.json",
        "scripts.setup.py",
        "scripts.executor.ps1",
        "data.snapshot.csv",
        "config.release.xml",
        "assets.package.lock",
        "images.preview.webp",
    ],
)
def test_schema_property_cannot_hide_file_like_missing_dependencies(
    tmp_path: Path, filename: str
) -> None:
    # A typed property row is not authority to discard an actual missing
    # executable, data file or artifact. A malicious schema should fail closed.
    source = HEADER + f"| `{filename}` | string | Required source artifact. |\n"
    result = resolve(tmp_path, source)
    assert result.complete is True
    assert any(
        row["status"] == "missing" and filename in row["evidence"]
        for row in result.records
    )


def test_unproven_schema_context_does_not_discard_missing_reference(tmp_path: Path) -> None:
    invalid = (
        "| File | Type | Description |\n|------|------|-------------|\n"
        "| `data.id` | uuid | Read from file. |\n",
        "| Field | Type | Description |\n"
        "| `data.id` | uuid | No delimiter. |\n",
        "| Field | Type | Description |\n|-------|------|-------------|\n"
        "| `data.id` | file | Real required file. |\n",
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
        HEADER
        + FIELD_ROWS
        + "Run `python3 scripts/required.sh` before continuing.\n"
        + "Read [bundle script](scripts/helper.py).\n",
    )
    missing = [row["evidence"] for row in result.records if row["status"] == "missing"]
    assert any("scripts/required.sh" in value for value in missing)
    assert any("scripts/helper.py" in value for value in missing)
    assert not any("data.payload.status" in value for value in missing)


def test_real_webhook_event_type_table_values_are_not_missing_paths(tmp_path: Path) -> None:
    # team-telnyx/ai@ee1dee2b5940ea9f370641746f82a3099918bbc4
    # skills/telnyx-whatsapp-java/SKILL.md, original lines 306-312.
    body = (
        HEADER
        + "| \x60event_type\x60 | string | \x60whatsapp.template.approved\x60, "
        "\x60whatsapp.template.rejected\x60, \x60whatsapp.template.disabled\x60 |\n"
        + "| \x60payload.status\x60 | string | New template status |\n"
    )
    result = resolve(tmp_path, body)
    assert result.complete is True
    assert result.records == []


def test_event_value_exemption_requires_exact_table_and_no_file_extensions(
    tmp_path: Path,
) -> None:
    descriptions = (
        "| \x60event_type\x60 | string | \x60config.data.json\x60, \x60reports.summary.md\x60 |\n",
        "| \x60config\x60 | string | \x60whatsapp.template.approved\x60, "
        "\x60whatsapp.template.rejected\x60 |\n",
        "| \x60event_type\x60 | file | \x60whatsapp.template.approved\x60, "
        "\x60whatsapp.template.rejected\x60 |\n",
        "| \x60event_type\x60 | string | Read \x60whatsapp.template.approved\x60, "
        "\x60whatsapp.template.rejected\x60 first |\n",
    )
    for line in descriptions:
        result = resolve(tmp_path, HEADER + line)
        assert result.complete is True
        assert any(row["status"] == "missing" for row in result.records), line
    no_header = resolve(
        tmp_path,
        "| \x60event_type\x60 | string | \x60whatsapp.template.approved\x60, "
        "\x60whatsapp.template.rejected\x60 |\n",
    )
    assert any(row["status"] == "missing" for row in no_header.records)


def test_real_no_llm_cli_schema_only_complete_but_missing_script_partial(tmp_path: Path) -> None:
    root = tmp_path / "skill"
    root.mkdir()
    header = "---\nname: webhook-schema\ndescription: Document a webhook schema.\n---\n"
    path = root / "SKILL.md"
    path.write_text(header + "### Webhook payload fields\n\n" + HEADER + FIELD_ROWS)
    before = path.read_bytes()
    cli = CliRunner()
    args = ["scan", str(root), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    clean = cli.invoke(app, args)
    assert clean.exit_code == 0, clean.output
    report = json.loads(clean.stdout)
    assert report["analysis_completeness"]["is_complete"] is True
    assert path.read_bytes() == before

    path.write_text(
        header + HEADER + FIELD_ROWS + "Run `python3 scripts/required.sh` before continuing.\n"
    )
    adverse = cli.invoke(app, args)
    assert adverse.exit_code == 1, adverse.output
    coverage = json.loads(adverse.stdout)["analysis_completeness"]
    assert coverage["status"] == "partial"
    assert coverage["is_complete"] is False
    assert any(
        row["status"] == "missing" and "scripts/required.sh" in row["evidence"]
        for row in coverage["references"]
    )
