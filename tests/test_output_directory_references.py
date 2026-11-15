# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Explicit output-directory CLI operands are not bundled input references."""

from pathlib import Path

import pytest

from skillspector.references import resolve_bundle_references_with_metadata


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
