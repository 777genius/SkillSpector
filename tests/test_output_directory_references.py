# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Explicit output-directory CLI operands are not bundled input references."""

import json
import runpy
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillspector.cli import app
from skillspector.references import (
    _is_output_directory_argument,
    resolve_bundle_references_with_metadata,
)


def resolve(tmp_path: Path, command: str):
    (tmp_path / "SKILL.md").write_text(
        "---\nname: output-directory-example\ndescription: Save generated results.\n---\n"
        "```bash\n" + command + "\n```\n",
        encoding="utf-8",
    )
    return resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=(tmp_path / "SKILL.md").read_text(encoding="utf-8"),
        known_paths=["SKILL.md"],
    )


@pytest.mark.parametrize(
    ("command", "output_path"),
    [
        ("gws gmail +watch --project my-project --cleanup --output-dir ./emails", "./emails"),
        (
            "lark-cli minutes +detail --minute-tokens token --transcript --output-dir ./transcripts --as user",
            "./transcripts",
        ),
        ("python3 scripts/download_results.py --urls URL1 URL2 --output-dir ./output", "./output"),
        (
            'asc web api-keys create --name uploads --role APP_MANAGER --output-dir "./keys" --output json',
            "./keys",
        ),
        (
            "python3 scripts/resize_sticker.py path/to/source.png --out-dir path/to/output-dir",
            "path/to/output-dir",
        ),
    ],
)
def test_explicit_output_directory_is_not_a_missing_input(
    tmp_path: Path, command: str, output_path: str
) -> None:
    result = resolve(tmp_path, command)
    assert result.complete is True
    output_column = command.index(output_path) + 1
    assert not any(
        item["line"] == 6 and item["column"] == output_column and item["status"] == "missing"
        for item in result.records
    )


@pytest.mark.parametrize(
    ("command", "path"),
    [
        ("python3 scripts/run.py --input-dir ./input", "./input"),
        ("python3 scripts/run.py --output-file ./output", "./output"),
        ("python3 scripts/run.py ./output", "./output"),
        ("python3 scripts/run.py --output-dir=./output", "./output"),
    ],
)
def test_non_directory_or_non_separate_operands_remain_references(
    tmp_path: Path, command: str, path: str
) -> None:
    result = resolve(tmp_path, command)
    expected_column = command.index(path) + 1
    assert any(
        item["line"] == 6 and item["column"] == expected_column and item["status"] == "missing"
        for item in result.records
    )


@pytest.mark.parametrize(
    ("command", "is_output"),
    [
        ('program --output-dir "./missing"', True),
        ("program --out-dir './missing'", True),
        ("program --output-dir ./missing", True),
        ("program --output-dir ./missing; echo done", True),
        ('program --output-dir "./missing' + "'", False),
        ("program --out-dir './missing" + '"', False),
        ("program --out-dir ./missing'", False),
        ('program --output-dir "./missing nextarg', False),
    ],
)
def test_output_directory_malformed_quote_never_suppresses_input(
    command: str, is_output: bool
) -> None:
    start = command.index("./missing")
    assert _is_output_directory_argument(command, start, start + len("./missing")) is is_output


def test_output_directory_does_not_hide_other_input_or_script_paths(tmp_path: Path) -> None:
    command = "python3 scripts/process.py ./input --output-dir ./output"
    result = resolve(tmp_path, command)
    missing_columns = {
        item["column"]
        for item in result.records
        if item["line"] == 6 and item["status"] == "missing"
    }
    assert command.index("./input") + 1 in missing_columns
    assert command.index("./output") + 1 not in missing_columns


def test_source_image_before_output_dir_remains_uninspected(tmp_path: Path) -> None:
    command = "python3 scripts/resize_sticker.py path/to/source.png --out-dir path/to/output-dir"
    result = resolve(tmp_path, command)
    assert any(
        item["status"] == "missing"
        and item["line"] == 6
        and item["column"] == command.index("path/to/source.png") + 1
        and "path/to/source.png" in item["evidence"]
        for item in result.records
    )
    # The output directory is not an input dependency. Its mere presence
    # must not hide the required source image or script operand.
    assert not any(
        item["status"] == "missing" and item["column"] == command.index("path/to/output-dir") + 1
        for item in result.records
    )


def test_real_inventory_overrides_output_directory_metadata(tmp_path: Path) -> None:
    source = "---\nname: output-inventory\ndescription: Preserve real source assets.\n---\n"
    source += "Run `program --output-dir ./LICENSE.txt` now.\n"
    (tmp_path / "SKILL.md").write_text(source, encoding="utf-8")
    (tmp_path / "LICENSE.txt").write_text("real bundled content", encoding="utf-8")
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=source,
        known_paths=["SKILL.md", "LICENSE.txt"],
    )
    assert any(
        row["status"] == "resolved" and row["target_path"] == "LICENSE.txt"
        for row in result.records
    )


@pytest.mark.parametrize(
    ("instruction", "required"),
    [
        ("> **PREREQUISITE:** Read `../shared/SKILL.md` for auth first.", True),
        ("**CRITICAL — MUST 先完整读取 [`../shared/SKILL.md`](../shared/SKILL.md)**", True),
        ("## See Also\n- [shared](../shared/SKILL.md)", False),
    ],
)
def test_mandatory_unacquired_sibling_is_not_certified(
    tmp_path: Path, instruction: str, required: bool
) -> None:
    source = (
        "---\nname: sibling-scope\ndescription: Test bounded source coverage.\n"
        "---\n# Skill\n" + instruction + "\n"
        "```bash\nexample-cli --output-dir ./results\n```\n"
    )
    (tmp_path / "SKILL.md").write_text(source, encoding="utf-8")
    scan = CliRunner().invoke(
        app, ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    )
    assert scan.exit_code in (0, 1), scan.output
    coverage = json.loads(scan.stdout)["analysis_completeness"]
    assert coverage["status"] == ("partial" if required else "complete")
    assert coverage["is_complete"] is (not required)
    assert any(
        ref["status"] == "rejected"
        and ref["disposition"] == "out_of_scope"
        and "../shared/SKILL.md" in ref["evidence"]
        for ref in coverage["references"]
    )
    assert not any(ref["status"] == "missing" for ref in coverage["references"])
    reasons = [item["reason_code"] for item in coverage["ledger_exceptions"]]
    assert ("referenced_uninspected" in reasons) is required
    if required:
        assert scan.exit_code == 1


def test_original_null_fingerprint_finding_is_not_skipped() -> None:
    """LP3 warnings in original signed v3 can legitimately have null fingerprints."""
    e2e = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "skillspector_2134_output_directory_e2e.py"
        )
    )
    preserve = e2e["ensure_signed_findings_preserved"]
    signed = {
        "rule": "LP3",
        "severity": "MEDIUM",
        "path": "SKILL.md",
        "line": 1,
        "match_fingerprint": None,
    }
    scanned = {
        "id": "LP3",
        "severity": "MEDIUM",
        "location": {"file": "SKILL.md", "start_line": 1},
        "match_fingerprint": None,
    }
    preserve([signed], [scanned], "pinned-source")
    with pytest.raises(ValueError, match="signed source-bound security finding lost"):
        preserve([signed], [], "pinned-source")
    with pytest.raises(ValueError, match="signed source-bound security finding lost"):
        preserve([signed, signed], [scanned], "pinned-source")
    with pytest.raises(ValueError, match="signed source-bound security finding lost"):
        preserve(
            [signed],
            [{**scanned, "location": {"file": "SKILL.md", "start_line": 2}}],
            "pinned-source",
        )


def test_risk_recommendation_cannot_be_weakened_by_e2e_exception() -> None:
    """Only exact SAFE -> CAUTION with all independent fields unchanged is allowed."""
    e2e = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "skillspector_2134_output_directory_e2e.py"
        )
    )
    escalation = e2e["conservative_risk_escalation"]
    safe = {
        "recommendation": "SAFE",
        "score": 0,
        "severity": "LOW",
        "max_issue_severity": "NONE",
    }
    caution = {**safe, "recommendation": "CAUTION"}
    assert escalation(safe, caution) is True
    assert escalation(caution, safe) is False
    assert escalation(safe, safe) is False
    assert escalation(safe, {**caution, "score": 1}) is False
    assert escalation(safe, {**caution, "severity": "HIGH"}) is False
    assert escalation(safe, {**caution, "max_issue_severity": "HIGH"}) is False
    assert escalation(safe, {**caution, "extra": "undocumented"}) is False
    assert escalation({**safe, "extra": "missing"}, caution) is False
    assert escalation(safe, {**safe, "recommendation": "UNKNOWN"}) is False
    assert escalation(None, caution) is False
