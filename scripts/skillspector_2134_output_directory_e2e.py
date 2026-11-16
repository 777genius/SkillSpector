#!/usr/bin/env python3
"""Pinned no-LLM E2E for runtime output-directory argument classification."""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

REPORT_COMMIT = "7771404dcdfc5b3855f1319b5e9a2bc19d0c7acf"
SOURCE_COMMIT = "a12bd3bdffab6991a2541220a16a0a9d6447e47e"
OLD_SCANNER = "c4816448b85fceaaf4291cb552e2de38562d1348"
DOMAIN = b"agentplugins.package-tree\x00sha256\x00v1"
UUID = re.compile(r"finding-[0-9a-f]{32}\Z")

CASES = (
    {
        "id": "googleworkspace/cli/gws-gmail-watch",
        "repository": "googleworkspace/cli",
        "revision": "cd3697e07eb520056dcf142d0c7439bbb9ba32e9",
        "source_path": "skills/gws-gmail-watch", "checkout": "source-google",
        "blob": "fca780f7e80a0ce814040861e2c40aeb3d4dd0da",
        "tree": "sha256:5a5ef8e684ddb6c6efb39ecf1632d413c7dfcc1f47b288065b523b6a60eb15f2",
        "entries": 1, "line": 47, "column": 62,
        "evidence": "gws gmail +watch --project my-project --cleanup --output-dir ./emails",
        # Mandatory sibling skill is outside the signed selected-root acquisition.
        "external_prerequisites": ("../gws-shared/SKILL.md",),
    },
    {
        "id": "larksuite/cli/lark-workflow-meeting-summary",
        "repository": "larksuite/cli",
        "revision": "3d82c85419ad7560ad017db7a3972a596b5fbeb1",
        "source_path": "skills/lark-workflow-meeting-summary", "checkout": "source-lark",
        "blob": "e48056c41da9eb664cac9feabe4e40bb5c8cbe66",
        "tree": "sha256:097dd64dab10e5cf59864f4cc4f1afeb3cc23e9dccaace02137691507511248b",
        "entries": 1, "line": 86, "column": 87,
        "evidence": '> lark-cli minutes +detail --minute-tokens "<minute_token>" --transcript --output-dir ./transcripts --as user',
        # The primary instructions explicitly MUST read both sibling skills.
        "external_prerequisites": ("../lark-shared/SKILL.md", "../lark-meeting/SKILL.md"),
    },
    {
        "id": "libtv-labs/libtv-skills/libtv-skill",
        "repository": "libtv-labs/libtv-skills",
        "revision": "c609246c1eca69f6bc129bcbb5d64c36734e4a4a",
        "source_path": "skills/libtv-skill", "checkout": "source-libtv",
        "blob": "b2088bae92f30dabc20a10b1c1bbd521638b9bf3",
        "tree": "sha256:71023efdc884b86fea8891888569111f6e74eaf702b847ad3c584237d2a1fd62",
        "entries": 8, "line": 114, "column": 82,
        "evidence": "python3 {baseDir}/scripts/download_results.py --urls URL1 URL2 URL3 --output-dir ./output",
        "signed_risks": (
            ("TT3", "CRITICAL", "scripts/_common.py", 46,
             "ed03e5371048cc42e689f66b85a00604a53054cecc17c2bfd9eb027ea516dc6f"),
            ("TT3", "CRITICAL", "scripts/_common.py", 62,
             "ed03e5371048cc42e689f66b85a00604a53054cecc17c2bfd9eb027ea516dc6f"),
        ),
    },
    {
        "id": "rorkai/app-store-connect-cli-skills/asc-cli-usage",
        "repository": "rorkai/app-store-connect-cli-skills",
        "revision": "266d7ad357acd3a1c437668b0e77021bb0ff2f02",
        "source_path": "skills/asc-cli-usage", "checkout": "source-asc",
        "blob": "be9c5e3420623ae3d44df4639368396350926497",
        "tree": "sha256:0bf1db33eb3a9112244a6464871ea154d6c901716a319caad43d212f9820d13e",
        "entries": 1, "line": 76, "column": 92,
        "evidence": "- Example: " + chr(96) + 'asc web api-keys create --name "CI uploads" --role APP_MANAGER --output-dir "./keys" --output json' + chr(96) + ".",
    },
    {
        "id": "zc277584121/marketing-skills/milvus-meme-sticker",
        "repository": "zc277584121/marketing-skills",
        "revision": "959680e17acfa4474639c7a9abf77340399ebfb6",
        "source_path": "skills/milvus-meme-sticker", "checkout": "source-sticker",
        "blob": "fb7e3fdc800fcba84fc74d5befe65b5ea6f07dbd",
        "tree": "sha256:75fc0e21349e6792f72fef783fd38a190a9c6c469b159f7bc92045b71d5d716b",
        "entries": 5, "line": 55, "column": 35,
        "evidence": "python3 scripts/resize_sticker.py path/to/source.png --out-dir path/to/output-dir",
        "negative_input": True,  # The reported missing path is source.png, NOT the output directory.
        "signed_risks": (
            ("AST4", "MEDIUM", "scripts/resize_sticker.py", 35,
             "41788c10cc8baa511900306d423c61c27dd365473f32d8d4aa75037282d9b3bc"),
        ),
    },
)

SHARDS = {
    "googleworkspace/cli": (811500, "sha256:7a6c76d6fc8c04884625f152befbff9e71c149a170fa99b39cb789145799ee12", 95),
    "larksuite/cli": (1373329, "sha256:02717a3ec3057c4d0f4030e138a887c2292c1d400cf82f3590c8c900eb2ea970", 25),
    "libtv-labs/libtv-skills": (12596, "sha256:15191ac9383e4d09541ae1a2e48b0c334265746c6864b30d14af70a90fac66b8", 1),
    "rorkai/app-store-connect-cli-skills": (398290, "sha256:8ccdccd419bd2bddcc11cd66187677f0f782fa2958da3d44a79a7255b1012dd6", 23),
    "zc277584121/marketing-skills": (219175, "sha256:adc5550ba8df656d7fbe25fb933616aabc284f05c41c490b4c284be96100f268", 14),
}


def git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def tree_digest(root: Path) -> tuple[str, int]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("source root is not a real directory")
    entries = []
    seen = set()
    total = 0
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        folded = relative.casefold()
        if path.is_symlink() or folded in seen or relative.startswith(".git/"):
            raise ValueError("source contains a symlink or colliding path")
        seen.add(folded)
        if path.is_dir():
            entries.append((relative.encode(), b"directory", b"040000", b"", b""))
        elif path.is_file():
            content = path.read_bytes()
            total += len(content)
            if total > 16 << 20 or len(entries) >= 2048:
                raise ValueError("source inventory exceeds audited bound")
            mode = b"100755" if path.stat().st_mode & 0o111 else b"100644"
            entries.append((relative.encode(), b"file", mode, b"", content))
        else:
            raise ValueError("source contains a special file")
    digest = hashlib.sha256()
    digest.update(len(DOMAIN).to_bytes(8, "big"))
    digest.update(DOMAIN)
    for relative, kind, mode, target, content in sorted(entries, key=lambda item: item[0]):
        for field in (b"entry", relative, kind, mode, target):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
        digest.update(len(content).to_bytes(8, "big"))
        if kind == b"file":
            digest.update(content)
    return "sha256:" + digest.hexdigest(), len(entries)


def canonical_issue(issue: dict) -> str:
    item = dict(issue)
    generated = item.get("finding_id")
    if isinstance(generated, str) and UUID.fullmatch(generated):
        item.pop("finding_id")
    return json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def issue_counter(report: dict) -> collections.Counter:
    issues = report.get("issues")
    if not isinstance(issues, list) or any(not isinstance(item, dict) for item in issues):
        raise ValueError("invalid security issue list")
    return collections.Counter(
        canonical_issue(item) for item in issues
        if not (item.get("id") in {"AE1", "AE7"} and item.get("tags") == ["coverage"])
    )


def conservative_risk_escalation(original: object, candidate: object) -> bool:
    """Only an explicit SAFE -> CAUTION change with identical other risk data.

    Never accept a downgrade, missing field, score/severity mutation or an
    unknown recommendation. A changed recommendation is reported in proof.
    """
    if not isinstance(original, dict) or not isinstance(candidate, dict):
        return False
    if original.keys() != candidate.keys():
        return False
    if original.get("recommendation") != "SAFE" or candidate.get("recommendation") != "CAUTION":
        return False
    return all(
        original[key] == candidate[key]
        for key in original if key != "recommendation"
    )


def ensure_signed_findings_preserved(
    signed_findings: list[dict], scanned_issues: list[dict], source_id: str
) -> None:
    """Require every authenticated security group, including null fingerprints."""
    expected: collections.Counter[tuple] = collections.Counter()
    for finding in signed_findings:
        if not isinstance(finding, dict):
            raise ValueError("invalid signed finding object: " + source_id)
        identity = (
            finding.get("rule"), finding.get("severity"), finding.get("path"),
            finding.get("line"), finding.get("match_fingerprint"),
        )
        if (
            not all(isinstance(value, str) and value for value in identity[:3])
            or not isinstance(identity[3], int)
            or isinstance(identity[3], bool)
            or (identity[4] is not None and (not isinstance(identity[4], str) or not identity[4]))
        ):
            raise ValueError("incomplete signed security finding identity: " + source_id)
        expected[identity] += 1

    observed: collections.Counter[tuple] = collections.Counter()
    if not isinstance(scanned_issues, list):
        raise ValueError("scanner security issues unavailable: " + source_id)
    for issue in scanned_issues:
        if not isinstance(issue, dict):
            raise ValueError("malformed scanner issue: " + source_id)
        location = issue.get("location")
        if isinstance(location, dict):
            observed[(
                issue.get("id"), issue.get("severity"), location.get("file"),
                location.get("start_line"), issue.get("match_fingerprint"),
            )] += 1
    if any(observed[identity] < count for identity, count in expected.items()):
        raise ValueError("signed source-bound security finding lost: " + source_id)


def scan(cli: Path, source: Path) -> tuple[dict, int]:
    with tempfile.TemporaryDirectory(prefix="output-dir-skillspector-home-") as home:
        env = {
            **os.environ, "HOME": home,
            "OPENAI_API_KEY": "", "ANTHROPIC_API_KEY": "",
            "GOOGLE_API_KEY": "", "GEMINI_API_KEY": "",
        }
        process = subprocess.run(
            [str(cli.resolve()), "scan", str(source.resolve()),
             "--no-llm", "--format", "json", "--fail-on-incomplete"],
            env=env, capture_output=True, text=True, timeout=180, check=False,
        )
    if process.returncode not in (0, 1):
        raise ValueError("scanner failed: " + process.stderr[-600:])
    report = json.loads(process.stdout)
    metadata = report.get("metadata", {})
    if (metadata.get("skillspector_version") != "2.13.4"
            or metadata.get("llm_requested") is not False
            or metadata.get("inference_usage") != []
            or report.get("execution_successful") is not True
            or report.get("suppressed_count") != 0
            or report.get("suppressed") != []):
        raise ValueError("scanner execution metadata or suppression boundary differs")
    return report, process.returncode


def verify_original_records(published: Path) -> dict:
    if git_head(published) != REPORT_COMMIT:
        raise ValueError("published reports checkout does not match original immutable commit")
    root = published / "reports/skillspector/v3"
    index = json.loads((root / "index.json").read_bytes())
    if (index.get("schema_version") != 3 or index.get("source_commit") != SOURCE_COMMIT
            or index.get("generated_at") != "2026-11-14T07:12:39Z"
            or index.get("scanner") != {
                "id": "skillspector", "version": "2.13.1",
                "revision": "f3b25697d76256998ca9d42c198d256258d4c035",
            }):
        raise ValueError("original signed catalog identity differs")
    descriptors = {item["repository"]: item for item in index["shards"]}
    verified = {}
    for case in CASES:
        repository = case["repository"]
        descriptor = descriptors.get(repository)
        expected_bytes, expected_digest, expected_count = SHARDS[repository]
        raw = (root / descriptor["path"]).read_bytes()
        if (descriptor["bytes"] != expected_bytes or len(raw) != expected_bytes
                or descriptor["digest"] != expected_digest
                or "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest
                or descriptor["record_count"] != expected_count):
            raise ValueError("original signed shard digest/size differs: " + repository)
        shard = json.loads(raw)
        if shard.get("repository") != repository or shard.get("schema_version") != 3:
            raise ValueError("wrong original signed shard")
        records = [item for item in shard["records"] if item.get("id") == case["id"]]
        if len(records) != 1:
            raise ValueError("original source record missing or ambiguous: " + case["id"])
        record = records[0]
        coverage = record.get("coverage", {})
        references = coverage.get("references", [])
        missing = [item for item in references if item.get("status") == "missing"]
        if (record.get("status") != "partial" or record.get("freshness") != "current"
                or record.get("source", {}).get("revision") != case["revision"]
                or record.get("source", {}).get("path") != case["source_path"]
                or record.get("source", {}).get("content_digest") != case["tree"]
                or [item.get("code") for item in coverage.get("reasons", [])] != ["reference_missing"]
                or coverage.get("grouping_complete") is not True
                or record.get("findings_truncated") is not False
                or coverage.get("reference_evidence_truncated") is not False
                or coverage.get("references_total") != len(references)
                or len(missing) != 1):
            raise ValueError("original status/coverage is not the audited sole-reference case")
        row = missing[0]
        if (row.get("line") != case["line"] or row.get("column") != case["column"]
                or row.get("reference_kind") != "plain_path" or row.get("source_path") != "SKILL.md"
                or row.get("evidence") != case["evidence"] or row.get("disposition") != "partial"
                or row.get("target_path") is not None):
            raise ValueError("original missing output-directory row differs: " + case["id"])
        verified[case["id"]] = record
    return verified


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--published", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    for case in CASES:
        parser.add_argument("--" + case["checkout"], type=Path, required=True)
    args = parser.parse_args()
    if git_head(args.baseline) != OLD_SCANNER:
        raise ValueError("baseline scanner revision differs")
    candidate_head = git_head(args.candidate)
    if not candidate_head:
        raise ValueError("candidate scanner revision missing")
    originals = verify_original_records(args.published)
    results = []
    for case in CASES:
        source_root = getattr(args, case["checkout"].replace("-", "_"))
        source = source_root / case["source_path"]
        if git_head(source_root) != case["revision"]:
            raise ValueError("source Git revision differs: " + case["id"])
        body = (source / "SKILL.md").read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(body)).encode("ascii") + b"\0" + body).hexdigest()
        digest, entries = tree_digest(source)
        if blob != case["blob"] or digest != case["tree"] or entries != case["entries"]:
            # Preserve a bounded, non-publishing proof even when a pinned Git
            # checkout differs from the historical acquired package.
            forensic = {
                "schema_version": 1,
                "kind": "immutable-source-tree-mismatch",
                "source_id": case["id"],
                "source_revision": case["revision"],
                "signed_skill_blob": case["blob"],
                "checkout_skill_blob": blob,
                "signed_tree_digest": case["tree"],
                "checkout_tree_digest": digest,
                "signed_entry_count": case["entries"],
                "checkout_entry_count": entries,
                "safe_for_automatic_publication": False,
                "production_modified": False,
            }
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(forensic, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            raise ValueError("immutable source blob/tree differs: " + case["id"])

        old, old_exit = scan(args.baseline / ".venv/bin/skillspector", source)
        if tree_digest(source)[0] != digest:
            raise ValueError("baseline scanner modified source: " + case["id"])
        new, new_exit = scan(args.candidate / ".venv/bin/skillspector", source)
        if tree_digest(source)[0] != digest:
            raise ValueError("candidate scanner modified source: " + case["id"])

        external_prerequisites = case.get("external_prerequisites", ())
        if any(required.encode("utf-8") not in body for required in external_prerequisites):
            raise ValueError("mandatory sibling instruction changed: " + case["id"])
        old_refs = old.get("analysis_completeness", {}).get("references")
        new_refs = new.get("analysis_completeness", {}).get("references")
        if not isinstance(old_refs, list) or not isinstance(new_refs, list):
            raise ValueError("reference evidence unavailable: " + case["id"])
        def key(value):
            return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        removed = collections.Counter(map(key, old_refs)) - collections.Counter(map(key, new_refs))
        added = collections.Counter(map(key, new_refs)) - collections.Counter(map(key, old_refs))
        expected = [item for item in old_refs
            if item.get("source_path") == "SKILL.md" and item.get("line") == case["line"]
            and item.get("column") == case["column"] and item.get("status") == "missing"
            and item.get("reference_kind") == "plain_path" and item.get("evidence") == case["evidence"]]
        if len(expected) != 1 or added:
            raise ValueError("original missing reference identity or new reference differs: " + case["id"])
        negative_input = case.get("negative_input", False)
        if negative_input:
            # The real published column points to path/to/source.png, which is
            # an INPUT, preceding --out-dir. Never certify it as an output.
            if removed or collections.Counter(map(key, new_refs)) != collections.Counter(map(key, old_refs)):
                raise ValueError("source image input was hidden: " + case["id"])
        elif removed != collections.Counter([key(expected[0])]):
            raise ValueError("unexpected output directory reference delta: " + case["id"])
        if issue_counter(old) != issue_counter(new):
            raise ValueError("security issue changed: " + case["id"])
        # Signed security findings must survive even if recommendation becomes
        # strictly more cautious. In particular preserve LP3 null fingerprints.
        original = originals[case["id"]]
        ensure_signed_findings_preserved(
            original.get("findings", []), new["issues"], case["id"]
        )
        old_risk = old.get("risk_assessment")
        new_risk = new.get("risk_assessment")
        risk_escalation = conservative_risk_escalation(old_risk, new_risk)
        if old_risk != new_risk and not risk_escalation:
            # Preserve the ORIGINAL failed proof instead of silently discarding it.
            # Diagnostic evidence is not a successful security comparison and
            # can never authorize a Complete/production promotion.
            original_risk = old.get("risk_assessment")
            candidate_risk = new.get("risk_assessment")
            def fingerprint(value):
                return hashlib.sha256(key(value).encode("utf-8")).hexdigest()
            original_fields = original_risk if isinstance(original_risk, dict) else {}
            candidate_fields = candidate_risk if isinstance(candidate_risk, dict) else {}
            changed_fields = sorted(
                k for k in set(original_fields) | set(candidate_fields)
                if original_fields.get(k) != candidate_fields.get(k)
            )
            diagnostic = {
                "schema_version": 1,
                "kind": "skillspector-2134-output-directory-failed-risk-comparison",
                "source_id": case["id"],
                "source_revision": case["revision"],
                "source_tree_sha256": digest,
                "old_scanner": OLD_SCANNER,
                "candidate_scanner": candidate_head,
                "original_risk_sha256": fingerprint(original_risk),
                "candidate_risk_sha256": fingerprint(candidate_risk),
                "changed_risk_fields": changed_fields,
                # Failure-only generated text; retain fail-closed mismatch rejection.
                # Limit rendered evidence; preserve full hashes and original lengths.
                "recommendation_delta": {
                    "original": original_fields["recommendation"][:2048]
                    if isinstance(original_fields.get("recommendation"), str) else None,
                    "candidate": candidate_fields["recommendation"][:2048]
                    if isinstance(candidate_fields.get("recommendation"), str) else None,
                    "original_length": len(original_fields["recommendation"])
                    if isinstance(original_fields.get("recommendation"), str) else None,
                    "candidate_length": len(candidate_fields["recommendation"])
                    if isinstance(candidate_fields.get("recommendation"), str) else None,
                },
                "old_risk_field_fingerprints": {
                    k: fingerprint(v) for k, v in sorted(original_fields.items())
                },
                "new_risk_field_fingerprints": {
                    k: fingerprint(v) for k, v in sorted(candidate_fields.items())
                },
                "comparison_passed": False,
                "security_proof_complete": False,
                "safe_for_automatic_publication": False,
                "production_partial_reduction": 0,
            }
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(diagnostic, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
            raise ValueError("independent security risk assessment changed: " + case["id"])
        for required in external_prerequisites:
            if not any(
                item.get("status") == "rejected"
                and item.get("disposition") == "out_of_scope"
                and required in item.get("evidence", "")
                for item in new_refs
            ):
                raise ValueError("mandatory unacquired sibling reference was hidden: " + case["id"])

        old_coverage = old["analysis_completeness"]
        coverage = new["analysis_completeness"]
        # Read-only bounded coverage diagnostics for real hosted failures.
        # Never infer Complete from the removal of one reference alone.
        print("OUTPUT_DIRECTORY_COVERAGE " + json.dumps({
            "source_id": case["id"],
            "old_status": old_coverage.get("status"),
            "new_status": coverage.get("status"),
            "old_is_complete": old_coverage.get("is_complete"),
            "new_is_complete": coverage.get("is_complete"),
            "old_exit": old_exit, "new_exit": new_exit,
            "uninspected_partial": coverage.get("partially_inspected_files"),
            "uninspected_entire": coverage.get("entirely_uninspected_files"),
            "new_ref_status_counts": dict(collections.Counter(
                item.get("status", "unknown") for item in new_refs
            )),
            "ledger_reason_codes": sorted({
                str(item.get("reason_code", ""))
                for item in coverage.get("ledger_exceptions", [])
                if isinstance(item, dict)
            }),
        }, sort_keys=True), flush=True)
        # Risk-bearing scans may exit 1 even when coverage is complete.
        # Exit 1 alone never qualifies or disqualifies coverage; a demonstrably
        # incomplete scan must nevertheless fail --fail-on-incomplete.
        if (old_coverage["status"] not in {"partial", "complete_with_caveats"}
                or (old_coverage["is_complete"] is False and old_exit != 1)
                or (coverage["is_complete"] is False and new_exit != 1)):
            raise ValueError("CLI status/exit contract differs: " + case["id"])
        if negative_input:
            if (not any(item.get("status") == "missing" and
                        item.get("line") == case["line"] and
                        item.get("column") == case["column"]
                        for item in new_refs)
                    or coverage.get("status") != "partial"
                    or coverage.get("is_complete") is not False
                    or new_exit != 1):
                raise ValueError("uninspected source image was falsely certified: " + case["id"])
        elif external_prerequisites:
            # Mandatory sibling Skills are outside this immutable acquisition.
            # Even complete_with_caveats/is_complete=True is not full coverage;
            # fail closed rather than treating a visible caveat as certification.
            if (coverage.get("status") != "partial"
                    or coverage.get("is_complete") is not False
                    or new_exit != 1):
                raise ValueError("mandatory external instructions falsely certified: " + case["id"])
        elif (coverage.get("status") != "complete"
                or coverage.get("is_complete") is not True
                or coverage.get("partially_inspected_files") != 0
                or coverage.get("entirely_uninspected_files") != 0
                or any(item.get("status") != "resolved" for item in new_refs)):
            raise ValueError("candidate did not produce a genuinely Complete output source: " + case["id"])
        results.append({
            "id": case["id"], "repository": case["repository"], "source_revision": case["revision"],
            "source_blob": blob, "source_tree_sha256": digest, "source_entries": entries,
            "removed_output_directory_reference_rows": 0 if negative_input else 1,
            "old_cli_status": old_coverage["status"],
            "new_cli_status": coverage["status"], "old_exit": old_exit, "new_exit": new_exit,
            "qualified_complete_candidate": not negative_input and not external_prerequisites,
            "negative_input_control": negative_input,
            "external_prerequisite_control": bool(external_prerequisites),
            "unacquired_required_sources": list(external_prerequisites),
            "original_signed_finding_groups": len(original.get("findings", [])),
            "security_findings_preserved": True, "source_bytes_unchanged": True,
            "conservative_risk_escalation": risk_escalation,
            "old_recommendation": old_risk.get("recommendation") if isinstance(old_risk, dict) else None,
            "new_recommendation": new_risk.get("recommendation") if isinstance(new_risk, dict) else None,
            "production_partial_reduction": 0,
        })
    receipt = {
        "schema_version": 1, "kind": "skillspector-2134-output-directory-source-e2e",
        "original_report_commit": REPORT_COMMIT, "original_source_commit": SOURCE_COMMIT,
        "old_scanner": OLD_SCANNER, "candidate_scanner": candidate_head,
        "source_count": len(results), "complete_candidates": sum(
            item["qualified_complete_candidate"] for item in results),
        "negative_input_controls": sum(item["negative_input_control"] for item in results),
        "external_prerequisite_controls": sum(
            item["external_prerequisite_control"] for item in results),
        "results": results,
        "safe_for_automatic_publication": False, "production_modified": False,
        "conservative_risk_escalations": sum(
            item["conservative_risk_escalation"] for item in results
        ),
        "production_partial_reduction": 0,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, subprocess.SubprocessError, ValueError) as exc:
        raise SystemExit("Output-directory native E2E rejected: " + str(exc)) from exc
