# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exact Cloudflare API-search term, with adversarial real-file controls."""

from pathlib import Path

import pytest

from skillspector.references import resolve_bundle_references_with_metadata

SEARCH = "Search: `blockConcurrencyWhile`, `idFromName`, `getByName`, `setAlarm`, `sql.exec`"
CALL = "\n\n```typescript\nconst rows = this.ctx.storage.sql.exec(\"SELECT 1\");\n```\n"


def resolve(root: Path, body: str, known: list[str] | None = None):
    return resolve_bundle_references_with_metadata(
        root,
        source_path="SKILL.md",
        source_text=body,
        known_paths=["SKILL.md"] if known is None else known,
    )


def test_documented_api_search_does_not_invent_missing_file(tmp_path: Path) -> None:
    result = resolve(tmp_path, SEARCH + CALL)
    assert result.complete, result.limitations
    assert result.raw_candidates_considered >= 1
    assert not [row for row in result.records if "sql.exec" in row["evidence"]]
    assert not any(row["status"] == "missing" for row in result.records)


@pytest.mark.parametrize(
    "body",
    [
        SEARCH,
        SEARCH + "\n\nMention .sql.exec without a call.",
        SEARCH + "\n\nThe method .sql.exec( is shown in prose, not a fenced example.",
        SEARCH + "\n\n```bash\necho .sql.exec(\n```",
        SEARCH + "\n\n```typescript\n// comment .sql.exec(\n```",
        SEARCH + "\n\n```typescript\nconst sample = \"this.ctx.storage.sql.exec(\";\n```",
        SEARCH + "\n\n```typescript\nconst sample = `this.ctx.storage.sql.exec(`;\n```",
        "Read `sql.exec` as a required file." + CALL,
        "Search: `blockConcurrencyWhile`, `idFromName`, `getByName`, `file.exec`" + CALL,
        "Search: `blockConcurrencyWhile`, `idFromName`, `sql.exec`" + CALL,
        "Search: `blockConcurrencyWhile`, `idFromName`, `getByName`, `sql.exec` and execute it" + CALL,
    ],
)
def test_unproven_or_explicit_file_use_stays_missing(tmp_path: Path, body: str) -> None:
    result = resolve(tmp_path, body)
    assert result.complete, result.limitations
    assert any(row["status"] == "missing" for row in result.records), result.records


def test_real_inventory_match_takes_precedence(tmp_path: Path) -> None:
    result = resolve(tmp_path, SEARCH + CALL, ["SKILL.md", "sql.exec"])
    assert result.complete
    assert any(
        row["status"] == "resolved" and row["target_path"] == "sql.exec"
        for row in result.records
    ), result.records


def test_same_token_independent_missing_link_stays_visible(tmp_path: Path) -> None:
    body = SEARCH + CALL + "\nLoad [the file](sql.exec) before running."
    result = resolve(tmp_path, body)
    assert result.complete
    assert any(
        row["status"] == "missing" and row["reference_kind"] == "markdown_link"
        for row in result.records
    ), result.records


def test_existing_uninspected_symlink_stays_partial(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-api-control"
    try:
        (tmp_path / "sql.exec").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    result = resolve(tmp_path, SEARCH + CALL)
    assert result.complete
    assert any(
        row["status"] == "uninspected" and row["disposition"] == "partial"
        for row in result.records
    ), result.records
