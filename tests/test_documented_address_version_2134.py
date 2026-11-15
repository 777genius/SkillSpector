# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""v2.13.4 fail-closed classification of documented IP/release literals."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillspector.cli import app
from skillspector.references import resolve_bundle_references_with_metadata


@pytest.mark.parametrize(
    ("body", "raw_count"),
    [
        ("Bind all servers to `0.0.0.0`, never localhost.", 1),
        ("No `localhost` or `127.0.0.1` in any environment variables.", 1),
        ("Use IPv4 address `192.168.10.20` on the network.", 1),
        ("Migrating from Skybridge `1.x` to `2.x`? Read the release notes.", 2),
        ("Version `0.36.x` is supported by the API.", 1),
    ],
)
def test_documented_ip_and_version_are_nonfile_literals(
    tmp_path: Path, body: str, raw_count: int
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=body, known_paths=["SKILL.md"]
    )
    assert result.complete
    assert result.raw_candidates_considered == raw_count
    assert result.accepted_references == 0
    assert result.records == []


@pytest.mark.parametrize(
    ("body", "target"),
    [
        ("The IPv4 file `0.0.0.0` is required.", "0.0.0.0"),
        ("Download `127.0.0.1` as a network address.", "127.0.0.1"),
        ("Read [IPv4 address](0.0.0.0).", "0.0.0.0"),
        ("The version file `1.x` is required.", "1.x"),
        ("Run `2.x` after upgrading.", "2.x"),
        ("The IPv4 address `300.1.2.3` is invalid.", "300.1.2.3"),
        ("The IPv4 address `127.000.000.001` is invalid.", "127.000.000.001"),
        ("Use `1.x`.", "1.x"),
        ("The IP address `127.0.0.1` is a required local file.", "127.0.0.1"),
        ("Use `0.0.0.0`.\nAn IPv4 address is documented next.", "0.0.0.0"),
        ("The version `1.2.3` is a required filename.", "1.2.3"),
    ],
)
def test_address_and_version_exemptions_cannot_hide_missing_artifacts(
    tmp_path: Path, body: str, target: str
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=body, known_paths=["SKILL.md"]
    )
    assert result.complete
    assert result.records
    assert all(ref["status"] == "missing" for ref in result.records)
    assert all(ref["target_path"] is None for ref in result.records)
    assert any(target in ref["evidence"] for ref in result.records)


@pytest.mark.parametrize(
    ("body", "target"),
    [
        ("Bind servers to IPv4 address `0.0.0.0`.", "0.0.0.0"),
        ("Migrating from version `1.x`?", "1.x"),
    ],
)
def test_real_file_inventory_overrides_nonfile_prose(
    tmp_path: Path, body: str, target: str
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=body, known_paths=["SKILL.md", target]
    )
    assert result.complete
    assert len(result.records) == 1
    assert result.records[0]["status"] == "resolved"
    assert result.records[0]["target_path"] == target


def test_real_no_llm_cli_keeps_missing_executable_incomplete(tmp_path: Path) -> None:
    source = tmp_path / "SKILL.md"
    source.write_text(
        "---\nname: literal-context\ndescription: Inspect network and version prose.\n---\n"
        "Bind all servers to `0.0.0.0`. Migrating from Skybridge `1.x` to `2.x`.\n",
        encoding="utf-8",
    )
    original = source.read_bytes()
    result = CliRunner().invoke(
        app, ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["execution_successful"] is True
    assert report["analysis_completeness"]["is_complete"] is True
    assert report["analysis_completeness"]["references"] == []
    assert source.read_bytes() == original

    with source.open("a", encoding="utf-8") as stream:
        stream.write("Run `python3 scripts/required.sh` before continuing.\n")
    incomplete = CliRunner().invoke(
        app, ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    )
    assert incomplete.exit_code == 1, incomplete.output
    report = json.loads(incomplete.stdout)
    assert report["analysis_completeness"]["is_complete"] is False
    assert any(
        ref["status"] == "missing" and "scripts/required.sh" in ref["evidence"]
        for ref in report["analysis_completeness"]["references"]
    )
