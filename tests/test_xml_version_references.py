# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Strict XML declarations cannot fabricate missing local references."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillspector.cli import app
from skillspector.references import resolve_bundle_references_with_metadata


@pytest.mark.parametrize("version", ["1.0", "1.1"])
@pytest.mark.parametrize("fenced", [False, True])
def test_xml_declaration_is_metadata(tmp_path: Path, version: str, fenced: bool) -> None:
    prolog = f'<?xml version="{version}" encoding="UTF-8"?>\n'
    source = "```xml\n" + prolog + "```\n" if fenced else prolog
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=source, known_paths=["SKILL.md"]
    )
    assert result.complete
    assert result.records == []


@pytest.mark.parametrize(
    "source",
    [
        'Read "1.0".\n',
        "Read [version file](1.0).\n",
        '<?xml version="1.x" encoding="UTF-8"?>\n',
        "<?xml version='1.0' encoding='UTF-8'?>\n",
        '<?xml version="1.0" encoding="UTF-8"?> and read "1.0"\n',
        'version="1.0"\n',
    ],
)
def test_non_declarations_keep_missing_evidence(tmp_path: Path, source: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=source, known_paths=["SKILL.md"]
    )
    assert result.complete
    assert any(ref["status"] == "missing" for ref in result.records)


@pytest.mark.parametrize("present", [False, True])
def test_version_shaped_filename_is_still_an_explicit_reference(
    tmp_path: Path, present: bool
) -> None:
    source = '```xml\n<?xml version="1.0" encoding="UTF-8"?>\n```\n'
    source += "Read [file](1.0).\n"
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=source,
        known_paths=["SKILL.md", "1.0"] if present else ["SKILL.md"],
    )
    assert result.complete
    assert len(result.records) == 1
    assert result.records[0]["status"] == ("resolved" if present else "missing")


def test_xml_only_real_cli_is_complete(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: xml-example\ndescription: Show XML sitemap examples.\n---\n"
        '```xml\n<?xml version="1.0" encoding="UTF-8"?>\n```\n',
        encoding="utf-8",
    )
    run = CliRunner().invoke(
        app,
        ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"],
    )
    assert run.exit_code == 0, run.output
    report = json.loads(run.stdout)
    assert report["analysis_completeness"]["is_complete"] is True
    assert report["analysis_completeness"]["references"] == []


def test_xml_prolog_does_not_hide_genuine_missing_script(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: xml-script\ndescription: Check a script dependency.\n---\n"
        '```xml\n<?xml version="1.0" encoding="UTF-8"?>\n```\n'
        "Run `python3 scripts/emit.py` now.\n",
        encoding="utf-8",
    )
    run = CliRunner().invoke(
        app,
        ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"],
    )
    assert run.exit_code == 1, run.output
    coverage = json.loads(run.stdout)["analysis_completeness"]
    assert coverage["is_complete"] is False
    assert any(ref["status"] == "missing" for ref in coverage["references"])
