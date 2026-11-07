# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resolve Markdown destinations without weakening missing-reference coverage."""

import base64
import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillspector import references as references_module
from skillspector.cli import app
from skillspector.mcp_server import run_scan
from skillspector.references import resolve_bundle_references_with_metadata


@pytest.mark.parametrize(
    ("source", "target"),
    [
        ("Read [guide](<docs/user guide.md>).", "docs/user guide.md"),
        (r'Read [guide](<docs/user guide.md> "A \"quoted\" title").', "docs/user guide.md"),
        (r"Read [guide](<docs/user guide.md> 'A \'quoted\' title').", "docs/user guide.md"),
        (r"Read [guide](<docs/user guide.md> (A \(quoted\) title)).", "docs/user guide.md"),
        (r"Read [guide](<\<note\>.md>).", "<note>.md"),
        (r"Read [manual](\<tool.1\>).", "<tool.1>"),
        ("Read [guide](<docs/user.md guide.md>).", "docs/user.md guide.md"),
        ("Read [guide](docs/guide(v1).md).", "docs/guide(v1).md"),
        (r"Read [guide](docs/guide\(v1\).md).", "docs/guide(v1).md"),
        ("Read [guide](docs/guide(a(b(c))).md).", "docs/guide(a(b(c))).md"),
        ('Read [guide](docs/guide.md "Guide title").', "docs/guide.md"),
        ("Read [guide][manual].\n\n[manual]: docs/user%20guide.md", "docs/user guide.md"),
        ("Read [guide][manual].\n\n[manual]: <docs/user guide.md>", "docs/user guide.md"),
        ("Read [guide][manual].\n\n[manual]: docs/guide(v1).md", "docs/guide(v1).md"),
        ("Read [guide](docs/part%23one.md#summary).", "docs/part#one.md"),
        ('[guide](docs/guide.md "see [sample](missing.md)")', "docs/guide.md"),
        ('[guide](docs/guide.md "missing.md")', "docs/guide.md"),
        ('[guide]: docs/guide.md "see docs/missing.md"', "docs/guide.md"),
        ("Read [guide](docs/part%3Fone.md?view=1).", "docs/part?one.md"),
        ("Read [guide](docs/part%252Fone.md).", "docs/part%2Fone.md"),
        ("Read [guide](docs/caf%C3%A9.md).", "docs/café.md"),
        ("Read [manual](tool.1).", "tool.1"),
        ("Read `tool.1`.", "tool.1"),
    ],
)
@pytest.mark.parametrize("present", [True, False])
def test_markdown_destinations_preserve_present_and_missing_targets(
    tmp_path: Path, source: str, target: str, present: bool
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=source,
        known_paths=["SKILL.md", target] if present else ["SKILL.md"],
    )
    assert result.complete is True  # Extraction completed; resolution may be missing.
    assert result.records
    assert {record["status"] for record in result.records} == {"resolved" if present else "missing"}
    assert {record["target_path"] for record in result.records} == {target if present else None}


@pytest.mark.parametrize(
    "target",
    ["../outside.md", "%2e%2e/outside.md", "%2Foutside.md", "%5Coutside.md", "C%3A/file.md"],
)
def test_decoded_destination_cannot_escape_bundle(tmp_path: Path, target: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=f"Read [guide]({target}).",
        known_paths=["SKILL.md"],
    )
    assert result.complete is True
    assert result.records
    assert all(record["status"] == "rejected" for record in result.records)


def test_reference_definitions_do_not_restore_slash_prose_false_positives(tmp_path: Path) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text="Compare process I/O, reads/writes, and environment/profile settings.",
        known_paths=["SKILL.md"],
    )
    assert result.complete is True
    assert result.records == []


@pytest.mark.parametrize(
    "body",
    [
        "Use the configuration field `worker_settings.region`.",
        "Inspect the object property\n`worker_settings.region`.",
        "Read the `worker_settings.region` field.",
        "The `worker_settings.region` field selects the worker location.",
        "Read\n`worker_settings.region` from live catalog evidence.",
        "Read `worker_settings.region` from the record data.",
        "Only `worker_settings.region`\ncarries the worker identity.",
        "The key `worker_settings.region` carries a value.",
        "Use the selector `job.runtime.pool`.",
    ],
)
def test_documented_scalar_fields_do_not_invent_missing_files(tmp_path: Path, body: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=body, known_paths=["SKILL.md"]
    )
    assert result.complete
    assert result.raw_candidates_considered == 1
    assert result.accepted_references == 0
    assert result.records == []


@pytest.mark.parametrize(
    "body",
    [
        "Read `worker_settings.region`.",
        "The field may be chosen later. Read `worker_settings.region`.",
        "Use `worker_settings.region`. The next field is optional.",
        "Use `worker_settings.region`\n\ncarries the worker identity.",
        "Configuration field [key](worker_settings.region).",
        "[Configuration field]: worker_settings.region",
        "Use the field `./worker_settings.region`.",
        "Use the field `config/worker_settings.region`.",
        'Use the field "worker_settings.region".',
        "Use the field 'worker_settings.region'.",
        "Use the field `worker_settings.region'.",
        r"Use the field \`worker_settings.region`.",
        "Use the field ``worker_settings.region``.",
        "`Example\nUse the field `worker_settings.region`.\n`",
        "```text\nUse the field `worker_settings.region`.\n```",
        "    Use the field `worker_settings.region`.",
        "<!-- Use the field `worker_settings.region`. -->",
        "---\ndescription: Use the field `worker_settings.region`.\n---",
        "Run `worker_settings.region` from live catalog evidence.",
        "Execute `worker_settings.region` from the record data.",
        "Source `worker_settings.region` from the record data.",
        "Invoke the field `worker_settings.region`.",
        "Call `worker_settings.region` from live catalog evidence.",
        "Launch `worker_settings.region` from live catalog evidence.",
        "Process `worker_settings.region` from live catalog evidence.",
        "Feed `worker_settings.region` from live catalog evidence.",
        "cat `worker_settings.region` from the record data.",
        "Read file `worker_settings.region` from the record data.",
        "Read `worker_settings.region` from the record data file.",
        "Open the configuration field `settings.yaml`.",
        "Read the configuration file `settings.toml`.",
        "python 'worker_settings.region' # field",
        "Use the field `worker_settings.region` | sh",
        "Use the field `worker_settings.123`.",
        "Use the field `worker-settings.region`.",
        "Use the field `" + "r" * 122 + ".region`.",
        "Use the field " + " " * 161 + "`worker_settings.region`.",
        "Invoke " + " " * 160 + "Read `worker_settings.region` from the record data.",
    ],
)
def test_ambiguous_or_explicit_file_uses_remain_missing(tmp_path: Path, body: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=body, known_paths=["SKILL.md"]
    )
    assert result.complete
    assert result.records
    assert all(record["status"] == "missing" for record in result.records)


@pytest.mark.parametrize(
    ("paths", "status", "target"),
    [
        (["worker_settings.region"], "resolved", "worker_settings.region"),
        (["docs/worker_settings.region"], "resolved", "docs/worker_settings.region"),
        (["a/worker_settings.region", "b/worker_settings.region"], "ambiguous", None),
    ],
)
def test_real_artifact_matches_override_documented_field_context(
    tmp_path: Path, paths: list[str], status: str, target: str | None
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text="Use the configuration field `worker_settings.region`.",
        known_paths=["SKILL.md", *paths],
    )
    assert result.complete
    assert len(result.records) == 1
    assert result.records[0]["status"] == status
    assert result.records[0]["target_path"] == target
    assert result.accepted_references == 1


@pytest.mark.parametrize(
    "file_use",
    [
        "Read [guide](worker_settings.region).",
        "Read `./worker_settings.region`.",
        "Read the file `worker_settings.region`.",
        "cat 'worker_settings.region'",
        "Read `worker_settings.region`.",
    ],
)
@pytest.mark.parametrize("separator", [" ", "\n\n"])
def test_field_context_does_not_exempt_other_uses_of_same_token(
    tmp_path: Path, file_use: str, separator: str
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text="Use the field `worker_settings.region`." + separator + file_use,
        known_paths=["SKILL.md"],
    )
    assert result.complete
    assert result.raw_candidates_considered == 2
    assert len(result.records) == 1
    assert result.records[0]["status"] == "missing"
    assert result.accepted_references == 1


def test_documented_fields_still_consume_the_candidate_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(references_module, "MAX_RAW_REFERENCE_CANDIDATES", 2)
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text="Use the field `worker_settings.region`.\n" * 3,
        known_paths=["SKILL.md"],
    )
    assert not result.complete
    assert result.limitations == ("raw_candidates",)
    assert result.raw_candidates_considered == 2
    assert result.records == []


@pytest.mark.parametrize("channel", ["cli", "mcp"])
@pytest.mark.parametrize("present", [True, False])
@pytest.mark.parametrize(
    ("body", "target"),
    [
        ("Read [guide][manual].\n\n[manual]: docs/user%20guide.md", "docs/user guide.md"),
        ("Read [guide](<docs/user.md guide.md>).", "docs/user.md guide.md"),
        (r'Read [guide](<docs/user guide.md> "A \"quoted\" title").', "docs/user guide.md"),
        (r"Read [guide](<docs/user guide.md> 'A \'quoted\' title').", "docs/user guide.md"),
        (r"Read [guide](<docs/user guide.md> (A \(quoted\) title)).", "docs/user guide.md"),
        (r"Read [guide](<\<note\>.md>).", "<note>.md"),
        (r"Read [manual](\<tool.1\>).", "<tool.1>"),
        ("Read [guide](docs/guide(v1).md).", "docs/guide(v1).md"),
        ("Read [guide](docs/part%23one.md#summary).", "docs/part#one.md"),
        ('[guide](docs/guide.md "see [sample](missing.md)")', "docs/guide.md"),
        ('[guide](docs/guide.md "missing.md")', "docs/guide.md"),
        ('[guide]: docs/guide.md "see docs/missing.md"', "docs/guide.md"),
    ],
)
async def test_cli_and_mcp_reference_completeness_agree(
    tmp_path: Path, body: str, target: str, present: bool, channel: str
) -> None:
    if "<" in target and os.name == "nt":
        pytest.skip("Literal angle filenames are unsupported on Windows")
    (tmp_path / "SKILL.md").write_text(
        f"---\nname: reference-control\ndescription: Summarize the guide.\n---\n{body}\n",
        encoding="utf-8",
    )
    if present:
        path = tmp_path / target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Guide\nSummarize the supplied text.\n", encoding="utf-8")
    if channel == "cli":
        result = CliRunner().invoke(
            app, ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"]
        )
        assert result.exit_code == (0 if present else 1), result.output
        report = json.loads(result.stdout)
    else:
        result = await run_scan(str(tmp_path), use_llm=False, output_format="json")
        # MCP keeps missing-reference-only caveats install-eligible while the
        # rendered report still exposes the incomplete analysis.
        assert result["safe_to_install"] is True
        report = json.loads(result["report"])
    assert report["execution_successful"] is True
    assert report["analysis_completeness"]["is_complete"] is present
    assert report["risk_assessment"]["recommendation"] == ("SAFE" if present else "CAUTION")
    assert {r["status"] for r in report["analysis_completeness"]["references"]} == {
        "resolved" if present else "missing"
    }


@pytest.mark.parametrize(
    ("body", "target"),
    [("Read [manual](tool.1).", "tool.1"), (r"Read [manual](\<tool.1\>).", "<tool.1>")],
)
async def test_numeric_extension_reference_retains_uninspected_artifact_gap(
    tmp_path: Path, body: str, target: str
) -> None:
    if "<" in target and os.name == "nt":
        pytest.skip("Literal angle filenames are unsupported on Windows")
    (tmp_path / "SKILL.md").write_text(f"# Guide\n{body}\n", encoding="utf-8")
    if target != "tool.1":
        (tmp_path / "tool.1").write_text(
            "# Safe decoy\nSummarize supplied text.\n", encoding="utf-8"
        )
    # A real raster artifact, independent of its man-page-like filename.
    (tmp_path / target).write_bytes(
        base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl6"
            "SAAAAABJRU5ErkJggg=="
        )
    )
    result = await run_scan(str(tmp_path), use_llm=False, output_format="json")
    report = json.loads(result["report"])
    assert result["safe_to_install"] is False
    assert report["analysis_completeness"]["is_complete"] is False
    assert any(r["target_path"] == target for r in report["analysis_completeness"]["references"])
    assert any(finding["id"] == "AE1" for finding in report["issues"])


@pytest.mark.parametrize("separator", ["%2F", "%5C"])
def test_encoded_directory_does_not_fall_back_to_another_basename(
    tmp_path: Path, separator: str
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=f"Read [guide](missing{separator}guide.md).",
        known_paths=["SKILL.md", "other/guide.md"],
    )
    assert result.complete is True
    assert len(result.records) == 1
    assert result.records[0]["status"] == "missing"
    assert result.records[0]["target_path"] is None


@pytest.mark.parametrize("body", ["[status]: All checks passed.", "[note]: Read the guide."])
def test_prose_after_bracket_label_is_not_a_reference(tmp_path: Path, body: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=body, known_paths=["SKILL.md"]
    )
    assert result.complete is True
    assert result.records == []


def test_escaped_angle_filename_does_not_resolve_different_file(tmp_path: Path) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=r"Read [manual](\<tool.1\>).",
        known_paths=["SKILL.md", "tool.1"],
    )
    assert len(result.records) == 1
    assert result.records[0]["status"] == "missing"
    assert result.records[0]["target_path"] is None


def test_malformed_markdown_openings_observe_deadline_before_yield(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = references_module._MARKDOWN_REFERENCE_START
    observed = 0

    class CountedStarts:
        def finditer(self, line: str):
            nonlocal observed
            for match in original.finditer(line):
                observed += 1
                yield match

    monkeypatch.setattr(references_module, "_MARKDOWN_REFERENCE_START", CountedStarts())
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text="[x](" * 5000,
        known_paths=["SKILL.md"],
        clock=lambda: observed / 1000,
    )
    assert "runtime" in result.limitations
    assert result.complete is False
    assert observed <= 2001


@pytest.mark.parametrize(
    "template", ["[guide]({})", "[guide](<{}>)", "[guide]: {}", "[guide]: <{}>"]
)
@pytest.mark.parametrize("length", [511, 512, 513])
def test_destination_length_limit_is_reported(tmp_path: Path, template: str, length: int) -> None:
    destination = "a%20/" * 100 + "x" * (length - 503) + ".md"
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=template.format(destination),
        known_paths=["SKILL.md"],
    )
    assert result.complete is (length <= 512)
    if length > 512:
        assert "markdown_destination" in result.limitations
    else:
        assert len(result.records) == 1
        assert result.records[0]["status"] == "missing"


@pytest.mark.parametrize("template", ['[guide](docs/a%20b.md "{}")', '[guide]: docs/a%20b.md "{}"'])
def test_title_length_limit_is_reported(tmp_path: Path, template: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=template.format("a" * 513),
        known_paths=["SKILL.md"],
    )
    assert result.complete is False
    assert "markdown_title" in result.limitations


@pytest.mark.parametrize("template", ['[guide](docs/guide.md "{}")', '[guide]: docs/guide.md "{}"'])
@pytest.mark.parametrize("title", ["see [sample](missing.md)", "missing.md", "see docs/missing.md"])
def test_title_text_is_not_a_reference(tmp_path: Path, template: str, title: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text=template.format(title) + "\n[other](docs/other.md)",
        known_paths=["SKILL.md", "docs/guide.md", "docs/other.md"],
    )
    assert result.complete is True
    assert [record["target_path"] for record in result.records] == [
        "docs/guide.md",
        "docs/other.md",
    ]


@pytest.mark.parametrize("channel", ["cli", "mcp"])
@pytest.mark.parametrize(
    "body",
    [
        "[guide]: " + "/".join(["a%20b"] * 90) + ".md",
        "[guide](<" + "a /" * 180 + "guide.md>)",
        '[guide](docs/a%20b.md "' + "a" * 513 + '")',
    ],
)
async def test_markdown_limits_block_complete_verdict(
    tmp_path: Path, body: str, channel: str
) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: reference-control\ndescription: Summarize the guide.\n---\n" + body + "\n",
        encoding="utf-8",
    )
    if channel == "cli":
        result = CliRunner().invoke(
            app, ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"]
        )
        assert result.exit_code == 1, result.output
        report = json.loads(result.stdout)
    else:
        result = await run_scan(str(tmp_path), use_llm=False, output_format="json")
        assert result["safe_to_install"] is False
        report = json.loads(result["report"])
    assert report["execution_successful"] is True
    assert report["analysis_completeness"]["is_complete"] is False


@pytest.mark.parametrize(
    ("body", "raw_count"),
    [
        (
            "Attribute the source only from the URL host "
            "(`agoda.com`, `trip.com`, `traveloka.com`) — not from a listing name.",
            3,
        ),
        ("Use the cookie domain `app.example.com` for the host allowlist.", 1),
        ("The hostname `api.example.org` identifies the public endpoint.", 1),
        ("The URL host `videos.example.net` identifies the endpoint.", 1),
    ],
)
def test_documented_url_hosts_are_not_missing_files(
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
    "body",
    [
        "Read the file `agoda.com` from the URL host list.",
        "Run `agoda.com` as the command for the URL host.",
        "Read [host](agoda.com).",
        'The URL host "agoda.com" was listed in the specification.',
        "Use `agoda.com`.",
        "The URL host `build.sh` invokes a local script.",
        "The domain `schema.json` is a JSON document.",
    ],
)
def test_url_host_context_does_not_hide_real_file_uses(tmp_path: Path, body: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=body, known_paths=["SKILL.md"]
    )
    assert result.complete
    assert result.records
    assert all(ref["status"] == "missing" for ref in result.records)


def test_documented_url_host_existing_artifact_is_still_scanned(tmp_path: Path) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text="Attribute the source only from the URL host (`agoda.com`).",
        known_paths=["SKILL.md", "agoda.com"],
    )
    assert result.complete
    assert len(result.records) == 1
    assert result.records[0]["status"] == "resolved"
    assert result.records[0]["target_path"] == "agoda.com"


def test_documented_url_hosts_strict_cli_finishes_without_missing_refs(
    tmp_path: Path,
) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: url-host-example\ndescription: Attribute source URLs to domains.\n---\n"
        "Attribute the source only from the URL host "
        "(`agoda.com`, `trip.com`, `traveloka.com`).\n",
        encoding="utf-8",
    )
    run = CliRunner().invoke(
        app, ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    )
    assert run.exit_code == 0, run.output
    report = json.loads(run.stdout)
    assert report["execution_successful"] is True
    assert report["analysis_completeness"]["is_complete"] is True
    assert report["analysis_completeness"]["references"] == []


@pytest.mark.parametrize(
    ("body", "missing_path"),
    [
        (
            "The hostname `api.example.org` is public. The local `config.ini` is required.",
            "config.ini",
        ),
        (
            "The URL host `agoda.com` is public; `settings.conf` is required.",
            "settings.conf",
        ),
        (
            "The domain `settings.ini` is a required local file.",
            "settings.ini",
        ),
        ("Download the URL host `agoda.com` before use.", "agoda.com"),
        ("The URL host `agoda.com` is the executable command.", "agoda.com"),
        ("The URL host `settings.ini` must be downloaded.", "settings.ini"),
        ("The domain `config.cfg` is required.", "config.cfg"),
        ("The URL host `data.csv` is listed.", "data.csv"),
        ("The URL host `bundle.zip` is public.", "bundle.zip"),
        ("The domain `package.lock` is listed.", "package.lock"),
    ],
)
def test_url_host_context_cannot_hide_local_artifacts(
    tmp_path: Path, body: str, missing_path: str
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=body, known_paths=["SKILL.md"]
    )
    assert result.complete
    assert len(result.records) == 1
    assert result.records[0]["status"] == "missing"
    # Missing references have no resolved inventory target; the evidence retains the literal path.
    assert result.records[0]["target_path"] is None
    assert missing_path in result.records[0]["evidence"]


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
def test_documented_ip_and_version_ranges_are_not_missing_files(
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
def test_documented_nonfile_context_keeps_actual_missing_paths(
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
def test_real_artifact_overrides_nonfile_literal_context(
    tmp_path: Path, body: str, target: str
) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=body, known_paths=["SKILL.md", target]
    )
    assert result.complete
    assert len(result.records) == 1
    assert result.records[0]["status"] == "resolved"
    assert result.records[0]["target_path"] == target


def test_documented_literals_strict_cli_preserves_missing_scripts(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: literal-context\ndescription: Inspect network and version prose.\n---\n"
        "Bind all servers to `0.0.0.0`. Migrating from Skybridge `1.x` to `2.x`.\n",
        encoding="utf-8",
    )
    run = CliRunner().invoke(
        app, ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    )
    assert run.exit_code == 0, run.output
    report = json.loads(run.stdout)
    assert report["execution_successful"] is True
    assert report["analysis_completeness"]["is_complete"] is True
    assert report["analysis_completeness"]["references"] == []

    with (tmp_path / "SKILL.md").open("a", encoding="utf-8") as source:
        source.write("Run [setup](scripts/required.sh) before continuing.\n")
    rejected = CliRunner().invoke(
        app, ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    )
    assert rejected.exit_code == 1, rejected.output
    report = json.loads(rejected.stdout)
    assert report["analysis_completeness"]["is_complete"] is False
    assert any(r["status"] == "missing" for r in report["analysis_completeness"]["references"])


@pytest.mark.parametrize(
    "body",
    [
        (
            "POST only: GET /api/v1/trends returns HTTP 404 (HTML, not JSON). "
            "Topics extracted daily; end yesterday or earlier and read `data.coverage`. "
            "`limit` defaults to 20."
        ),
        (
            "| Endpoint | Method | Details |\n"
            "| /api/v1/trends | POST | Today is computed next morning - read `data.coverage`. |"
        ),
        (
            "### Trends - POST only\n\n"
            "`GET /api/v1/trends` returns HTTP 404; empty POST body is accepted.\n\n"
            "Topics are extracted daily; end yesterday or earlier and read `data.coverage`."
        ),
        ("POST /api/v1/trends returns a JSON response.\n\nRead `data.coverage`."),
        (
            "### Trends - POST only\n\n"
            "curl -X POST https://example.test/api/v1/trends\n\n"
            "Topics are extracted daily; read `data.coverage`."
        ),
    ],
)
def test_http_response_data_coverage_is_not_a_missing_file(tmp_path: Path, body: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=body, known_paths=["SKILL.md"]
    )
    assert result.complete
    assert result.records == []
    assert result.accepted_references == 0


@pytest.mark.parametrize(
    "body",
    [
        "Read `data.coverage`.",
        "POST /api/v1/trends: Read the file `data.coverage`.",
        "POST /api/v1/trends: Read `data.coverage` from a local project file.",
        "POST /api/v1/trends: Run `data.coverage` as the executable.",
        "POST /api/v1/trends: Download `data.coverage` from the server.",
        "POST /api/v1/trends: Read [the local file](data.coverage).",
        "POST /api/v1/trends: Read `data.coverage` file.",
        "POST /api/v1/trends documents the endpoint.\n\nRead `data.coverage`.",
        "POST /api/v1/trends: Read `data.sh`.",
        "GET and POST methods are available. Read `data.coverage`.",
        "### API\nPOST /api/v1/trends returns JSON.\n\n### Local files\nRead `data.coverage`.",
    ],
)
def test_http_api_context_never_hides_real_missing_files(tmp_path: Path, body: str) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path, source_path="SKILL.md", source_text=body, known_paths=["SKILL.md"]
    )
    assert result.complete
    assert result.records
    assert all(ref["status"] == "missing" for ref in result.records)


def test_http_coverage_field_present_in_local_inventory_is_resolved(tmp_path: Path) -> None:
    result = resolve_bundle_references_with_metadata(
        tmp_path,
        source_path="SKILL.md",
        source_text="POST /api/v1/trends returns JSON; read `data.coverage`.",
        known_paths=["SKILL.md", "data.coverage"],
    )
    assert result.complete
    assert len(result.records) == 1
    assert result.records[0]["status"] == "resolved"
    assert result.records[0]["target_path"] == "data.coverage"


def test_http_coverage_field_strict_no_llm_cli_and_missing_script(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: api-coverage-example\ndescription: Read response JSON fields.\n---\n"
        "POST /api/v1/trends returns JSON. End at yesterday and read `data.coverage`.\n",
        encoding="utf-8",
    )
    command = ["scan", str(tmp_path), "--no-llm", "--format", "json", "--fail-on-incomplete"]
    clean = CliRunner().invoke(app, command)
    assert clean.exit_code == 0, clean.output
    clean_coverage = json.loads(clean.stdout)["analysis_completeness"]
    assert clean_coverage["is_complete"] is True
    assert clean_coverage["references"] == []

    with (tmp_path / "SKILL.md").open("a", encoding="utf-8") as stream:
        stream.write(
            "Run [the required setup script](scripts/required.sh) before using the Skill.\n"
        )
    incomplete = CliRunner().invoke(app, command)
    assert incomplete.exit_code == 1, incomplete.output
    missing = json.loads(incomplete.stdout)["analysis_completeness"]
    assert missing["is_complete"] is False
    assert any(ref["status"] == "missing" for ref in missing["references"])
