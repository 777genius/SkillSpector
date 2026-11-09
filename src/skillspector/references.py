# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bounded canonical resolver for references made by the primary skill file."""

from __future__ import annotations

import hashlib
import heapq
import ipaddress
import posixpath
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from io import StringIO
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

import yaml

from skillspector.artifacts import ArtifactDisposition, BundleReference, ReferenceKind

MAX_REFERENCE_SOURCE_BYTES = 1_000_000
MAX_RAW_REFERENCE_CANDIDATES = 4096
MAX_ACCEPTED_REFERENCES = 256
MAX_REFERENCE_RECORDS = 1024
MAX_REFERENCE_RUNTIME_SECONDS = 2.0
_MAX_VERSION_FRONTMATTER_CHARS = 64 * 1024
_MAX_EVIDENCE = 160
_MAX_MARKDOWN_DESTINATION_CHARS = 512
_MARKDOWN_REFERENCE_START = re.compile(
    r"(?:!\[[^\]\n]{0,200}\]|(?<!!)\[[^\]\n]{1,200}\])\("
    r"|^[ \t]{0,3}\[[^\]\n]{1,200}\]:[ \t]*"
)
_MARKDOWN_TITLE = r"""(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|\((?:\\.|[^)\\\r\n])*\))"""
_MARKDOWN_INLINE_END = re.compile(r"[ \t]*(?:" + _MARKDOWN_TITLE + r")?[ \t]*\)")
_MARKDOWN_DEFINITION_END = re.compile(r"[ \t]*(?:" + _MARKDOWN_TITLE + r")?[ \t]*(?:\r?\n)?\Z")
_MARKDOWN_STRUCTURAL_ESCAPE = re.compile(r"\\([\\()<>])")
_PASSIVE_IMAGE_DESTINATION = re.compile(
    r"[^\s\\()\[\]<>]+(?:[ \t]+(?:\"[^\"\\\r\n()]*\"|'[^'\\\r\n()]*'))?"
)
_MARKDOWN_FENCE = re.compile(r"^[ ]{0,3}(`{3,}|~{3,})([^\r\n]*)$")
_MARKDOWN_CONTAINER_PREFIX = re.compile(
    r"[ ]{0,3}(?:(>)[ ]?|(?:[-+*]|\d{1,9}[.)])(?:[ ]{1,4}(?![ ])|[ ](?=[ ]{4})))"
)
_HTML_CONTEXT_START = re.compile(
    r"<!--|<\?|<!\[CDATA\[|<![A-Z]|</?([A-Za-z][A-Za-z0-9-]*)(?=[\s/>])",
    re.IGNORECASE,
)
_FRONTMATTER_VERSION = re.compile(
    r"""^[ \t]*(?:version|'version'|"version"|[a-z][a-z0-9_-]{0,63}-version|'[a-z][a-z0-9_-]{0,63}-version'|"[a-z][a-z0-9_-]{0,63}-version"):[ \t]*(['"])"""
    r"(?P<version>v?[0-9]+(?:\.[0-9]+)+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)"
    r"\1(?=[ \t]*(?:#|\r?$))"
)
# Only a complete, strict JSON VERSION field is proven metadata. Never
# suppress numeric paths or other quoted references by value alone.
_JSON_VERSION_FIELD = re.compile(
    r'^[ \t]*"VERSION"[ \t]*:[ \t]*"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"[ \t]*,?[ \t]*$'
)
# A complete XML prolog is markup, not a bundled-file reference.
# Keep this syntax gate strict; explicit version-shaped file links still count.
_XML_VERSION_DECLARATION = re.compile(
    r'^[ \t]*<\?xml[ \t]+version="(?P<version>1\.[01])"[ \t]+encoding="UTF-8"[ \t]*\?>[ \t]*$'
)
_QUOTED_OR_CODE_PATH = re.compile(
    r"(?:`|'|\")((?:\./)?(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,12})(?:`|'|\")"
)
# A declaration is a complete documentation line, not a command operand or a
# claim inferred from nearby natural-language instructions. Keep the initial
# grammar intentionally smaller than Markdown's general inline-code grammar.
_DOCUMENTATION_IMAGE_DECLARATION = re.compile(
    r"(?:Asset|Image|Illustration|Diagram|Figure|Screenshot|Photo|Picture)"
    r":[ \t]+`((?:\./)?(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:png|jpg|jpeg))`"
    r"\.?[ \t]*",
    re.IGNORECASE,
)
# An interpreter command is an explicit path signal, but only its immediate
# script operand is eligible.  Searching the rest of the code span would turn
# strings passed to ``-c``/``-e`` and option values into fabricated references.
_INLINE_CODE_COMMAND_PATH = re.compile(
    r"`(?:python(?:\d+(?:\.\d+)*)?|py|node|deno|bun|bash|sh|zsh|fish|ruby|perl|php|"
    r"pwsh|powershell)\b[ \t]+"
    # Bound known interpreter switches; never parse eval -c/-e operands as scripts.
    r"(?:(?:-u|-B|-I|-S|-E|-s|-v|-O|-OO|--)[ \t]+){0,2}"
    r"((?:\./)?(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+)(?![\w/.-])"
)
_DOTTED_IDENTIFIER = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", re.ASCII)
_DATA_FIELD_PREFIX = re.compile(
    r"(?:(?:Use|Inspect|Read|Check)[ \t\r\n]+)?(?:the[ \t\r\n]+|a[ \t\r\n]+)?"
    r"(?:(?:configuration|config|object|record)[ \t\r\n]+)?"
    r"(?:field|property|key|selector):?",
    re.IGNORECASE,
)
_DATA_FIELD_READ_PREFIX = re.compile(
    r"(?:Use|Inspect|Read|Check)(?:[ \t\r\n]+(?:the|a))?|The", re.IGNORECASE
)
_DATA_FIELD_SUFFIX = re.compile(
    r"[ \t\r\n]+(?:"
    r"(?:field|property|key|selector)\b|"
    r"from[ \t\r\n]+(?:the[ \t\r\n]+)?(?:live[ \t\r\n]+)?"
    r"(?:catalog|record|object|configuration)[ \t\r\n]+(?:data|evidence|values)\b)",
    re.IGNORECASE,
)
_DATA_FIELD_SCALAR_SUFFIX = re.compile(
    r"[ \t\r\n]+carries[ \t\r\n]+(?:the|a)[ \t\r\n]+"
    r"(?:[A-Za-z][A-Za-z_-]{0,31}[ \t\r\n]+)?(?:identity|value)\b",
    re.IGNORECASE,
)
_DATA_FIELD_CLAUSE_END = re.compile(r"[;!?]|\.[ \t\r\n]|\r?\n[ \t]*\r?\n")
_DATA_FIELD_FILE_CONTEXT = re.compile(
    r"\b(?:files?|filenames?|paths?|directories|directory|scripts?|commands?|"
    r"run|execute|source|open|load|import|include|download|upload|copy|move|delete|"
    r"cat|less|more|head|tail|grep|sed|awk|bash|sh|zsh|python\d*|node|perl|ruby|"
    r"curl|wget|chmod|cp|mv|rm)\b|[$|&<>\\]",
    re.IGNORECASE,
)


def _is_documented_data_field(text: str, start: int, end: int) -> bool:
    """Recognize bounded, adjacent prose about a scalar rather than an artifact."""
    if end - start > 128 or _DOTTED_IDENTIFIER.fullmatch(text, start, end) is None:
        return False
    if (
        start < 1
        or end >= len(text)
        or text[start - 1] != "`"
        or text[end] != "`"
        or (start > 1 and text[start - 2] in "`\\")
        or (end + 1 < len(text) and text[end + 1] == "`")
    ):
        return False
    context_start = max(0, start - 161)
    clauses = _DATA_FIELD_CLAUSE_END.split(text[context_start : start - 1])
    if context_start and len(clauses) == 1:
        return False
    before = clauses[-1].strip()
    after = _DATA_FIELD_CLAUSE_END.split(text[end + 1 : end + 161], maxsplit=1)[0]
    if _DATA_FIELD_FILE_CONTEXT.search(before) or _DATA_FIELD_FILE_CONTEXT.search(after):
        return False
    return bool(
        _DATA_FIELD_PREFIX.fullmatch(before)
        or (_DATA_FIELD_READ_PREFIX.fullmatch(before) and _DATA_FIELD_SUFFIX.match(after))
        or (before.lower() in {"only", "the"} and _DATA_FIELD_SCALAR_SUFFIX.match(after))
    )


# A schema table documents scalar fields; it is not an artifact inventory.
# Require the exact table header and type column. Explicit file uses and real
# inventory matches continue through normal fail-closed reference resolution.
_SCHEMA_TABLE_TYPES = frozenset({
    "uuid", "uri", "url", "string", "integer", "int", "number", "decimal",
    "float", "boolean", "bool", "date-time", "datetime", "timestamp",
    "object", "array",
})
_SCHEMA_FILE_SUFFIXES = frozenset({
    "json", "md", "py", "js", "ts", "jsx", "tsx", "sh", "yaml", "yml",
    "toml", "txt", "csv", "sql", "ini", "env", "html", "xml", "css",
    "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "pdf", "jar",
    "exe", "bat", "cmd", "ps1", "dll", "so", "dylib", "wasm", "bin",
    "go", "rs", "c", "h", "java", "class", "lock", "db", "sqlite",
})
_SCHEMA_API_HEADING = re.compile(
    r"^#{1,6}[ \t]+(?:(?:webhook|api|http|json|request|response|event)"
    r"\b[^\r\n]{0,80}\b(?:fields?|schema|properties)|"
    r"(?:fields?|schema|properties)\b[^\r\n]{0,80}\b"
    r"(?:webhook|api|http|json|request|response|event))\b",
    re.IGNORECASE,
)
_SCHEMA_ARTIFACT_HEADING = re.compile(
    r"\b(?:required[ \t]+)?(?:scripts?|files?|artifacts?|dependencies|"
    r"executables?|commands?|binaries|attachments?)\b",
    re.IGNORECASE,
)

def _is_documented_schema_table_field(text: str, start: int, end: int) -> bool:
    """Match bounded Markdown API property rows, never a real missing file."""
    field = text[start:end]
    if (end - start > 128 or _DOTTED_IDENTIFIER.fullmatch(field) is None
            or not field.startswith(("data.", "meta."))):
        return False
    if field.rsplit(".", 1)[-1].lower() in _SCHEMA_FILE_SUFFIXES:
        return False
    if start < 1 or end >= len(text) or text[start - 1] != "`" or text[end] != "`":
        return False
    if (start > 1 and text[start - 2] in ("`", "\\")
            or end + 1 < len(text) and text[end + 1] == "`"):
        return False
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    if line_end - line_start > 512:
        return False
    cells = text[line_start:line_end].split("|")
    if (len(cells) != 5 or cells[0].strip() or cells[-1].strip()
            or cells[1].strip() != f"`{field}`" or not cells[3].strip()
            or _DATA_FIELD_FILE_CONTEXT.search(cells[3])):
        return False
    field_type = cells[2].strip().lower()
    if field_type not in _SCHEMA_TABLE_TYPES and re.fullmatch(
            r"enum: [a-z0-9_.-]+(?:, [a-z0-9_.-]+){0,8}", field_type) is None:
        return False
    preceding = text[max(0, line_start - 4096):line_start].splitlines()
    rows = []
    for row in reversed(preceding):
        if not row.lstrip().startswith("|"):
            break
        rows.append(row)
        if len(rows) > 64:
            return False
    rows.reverse()
    header = re.sub(r"\s", "", rows[0]).lower() if rows else ""
    if (len(rows) < 2 or header != "|field|type|description|" or
            re.fullmatch(r"[ \t]*\|[ \t]*:?-{3,}:?[ \t]*\|"
                         r"[ \t]*:?-{3,}:?[ \t]*\|"
                         r"[ \t]*:?-{3,}:?[ \t]*\|[ \t]*", rows[1]) is None):
        return False
    # Typed columns alone are ambiguous: require an actual nearby API heading.
    # A table of required scripts must never make a missing file disappear.
    header_offset = line_start - sum(len(row) + 1 for row in rows)
    nearby = text[max(0, header_offset - 256):header_offset].splitlines()
    heading = next((row.strip() for row in reversed(nearby) if row.lstrip().startswith("#")), "")
    return (_SCHEMA_API_HEADING.match(heading) is not None
            and _SCHEMA_ARTIFACT_HEADING.search(heading) is None)


# A literal domain listed as a URL host is not a local file dependency. Keep
# this exception bounded to unescaped single-backtick prose; actual inventory
# matches and explicit file/command uses still take precedence.
_DOCUMENTED_URL_HOST = re.compile(r"\b(?:URL[ \t]+hosts?|hostnames?|domains?)\b", re.IGNORECASE)
_DOCUMENTED_URL_HOST_FILE_USE = re.compile(
    r"\b(?:files?|filenames?|paths?|scripts?|commands?|read|run|execut\w*|open|load|"
    r"include|import|download\w*|upload\w*|cop(?:y|ied|ying)|mov(?:e|es|ed|ing)|"
    r"delet\w*|install\w*)\b",
    re.IGNORECASE,
)


def _is_documented_url_hostname(text: str, start: int, end: int) -> bool:
    if end - start > 128 or _DOTTED_IDENTIFIER.fullmatch(text, start, end) is None:
        return False
    if (
        start < 1
        or end >= len(text)
        or text[start - 1] != "`"
        or text[end] != "`"
        or (start > 1 and text[start - 2] in "`\\")
        or (end + 1 < len(text) and text[end + 1] == "`")
    ):
        return False
    # Only demonstrated DNS suffixes qualify for this bounded prose exception.
    # An unknown suffix can be a local artifact (e.g. data.csv or bundle.zip);
    # retain its missing-reference evidence instead of guessing a hostname.
    tld = text[start:end].rsplit(".", 1)[-1]
    if tld.lower() not in {"com", "org", "net"}:
        return False
    # Never cross a line boundary or interpret an instruction to use a file
    # as documentation of a hostname.
    # A host qualifier in a previous sentence cannot excuse a missing local
    # file on the same line. Explicit file use after the token also wins.
    before = _DATA_FIELD_CLAUSE_END.split(text[max(0, start - 96) : start - 1])[-1]
    after = _DATA_FIELD_CLAUSE_END.split(text[end + 1 : end + 97], maxsplit=1)[0]
    return (
        bool(_DOCUMENTED_URL_HOST.search(before))
        and not _DOCUMENTED_URL_HOST_FILE_USE.search(before)
        and not _DOCUMENTED_URL_HOST_FILE_USE.search(after)
    )


# IPv4 addresses and dotted version ranges are not local file dependencies
# when their immediate prose explicitly documents their meaning. Real
# inventory matches, Markdown links and file/command uses still win.
_DOCUMENTED_LITERAL_CLAUSE_END = re.compile(r"[;!?]|\.[ \t\r\n]|\r?\n")
_IPV4_LITERAL = re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", re.ASCII)
_IPV4_PROSE = re.compile(
    r"\b(?:ipv4|ip|addresses?|hosts?|hostnames?|servers?|localhost|loopback|"
    r"bind(?:ing)?|listen(?:ing)?|network|dns)\b",
    re.IGNORECASE,
)
_VERSION_RANGE_LITERAL = re.compile(r"v?[0-9]+(?:\.[0-9]+){0,2}\.[xX]", re.ASCII)
_VERSION_RANGE_PROSE = re.compile(
    r"\b(?:versions?|migrat(?:e|ing|ion)|upgrad(?:e|ing)|releases?|semver)\b",
    re.IGNORECASE,
)


def _is_documented_address_or_version(text: str, start: int, end: int) -> bool:
    if not 3 <= end - start <= 24 or start < 1 or end >= len(text):
        return False
    if (
        text[start - 1] != "`"
        or text[end] != "`"
        or (start > 1 and text[start - 2] in "`\\")
        or (end + 1 < len(text) and text[end + 1] == "`")
    ):
        return False
    token = text[start:end]
    qualifier = None
    if _IPV4_LITERAL.fullmatch(token):
        try:
            ipaddress.IPv4Address(token)
        except ipaddress.AddressValueError:
            return False
        qualifier = _IPV4_PROSE
    elif _VERSION_RANGE_LITERAL.fullmatch(token):
        qualifier = _VERSION_RANGE_PROSE
    if qualifier is None:
        return False
    # No qualifier may leak across a line or a sentence; a file operation
    # anywhere in the current clause disqualifies this narrow exemption.
    before = _DOCUMENTED_LITERAL_CLAUSE_END.split(text[max(0, start - 96) : start - 1])[-1]
    after = _DOCUMENTED_LITERAL_CLAUSE_END.split(text[end + 1 : end + 97], maxsplit=1)[0]
    return (
        bool(qualifier.search(before) or qualifier.search(after))
        and not _DOCUMENTED_URL_HOST_FILE_USE.search(before)
        and not _DOCUMENTED_URL_HOST_FILE_USE.search(after)
    )


# An API response property may look like a file in Markdown inline code.
# This exception is limited to an observed response field in one bounded
# API section with a verified endpoint. Inventory and local-file usage win.
_API_COVERAGE_METHOD = re.compile(r"\b(?:GET|POST)\b")
_API_COVERAGE_ROUTE = re.compile(r"/api/v1/trends(?![\w/-])", re.IGNORECASE)
_API_COVERAGE_RESPONSE = re.compile(
    r"\b(?:json|response|returns?|topics?|entities|extracted|computed)\b",
    re.IGNORECASE,
)
_API_COVERAGE_FILE_USE = re.compile(
    r"\b(?:files?|filenames?|paths?|scripts?|commands?|local|project|workspace|"
    r"directories|folders?|execut\w*|run|download\w*|install\w*|upload\w*|"
    r"write|create|open|load|import|include)\b",
    re.IGNORECASE,
)
_API_COVERAGE_READ = re.compile(r"\bread[ \t]*`$", re.IGNORECASE)


def _is_documented_api_coverage_field(text: str, start: int, end: int) -> bool:
    """Skip only a verified inline HTTP response property, never a local path."""
    if text[start:end] != "data.coverage" or start < 1 or end >= len(text):
        return False
    if (
        text[start - 1] != chr(96)
        or text[end] != chr(96)
        or (start > 1 and text[start - 2] in (chr(96), chr(92)))
        or (end + 1 < len(text) and text[end + 1] == chr(96))
    ):
        return False
    # The real API can document POST in a preceding paragraph. Only accept
    # that context inside the same bounded Markdown section with the exact
    # observed route; unrelated GET/POST prose is not sufficient proof.
    section = re.split(r"(?m)^#{1,6}[ \t]+", text[max(0, start - 1200) : start])[-1]
    preceding = section.rsplit("\n\n", 1)[-1]
    if (
        not _API_COVERAGE_METHOD.search(section)
        or not _API_COVERAGE_ROUTE.search(section)
        or not _API_COVERAGE_RESPONSE.search(section)
        or _API_COVERAGE_FILE_USE.search(section)
    ):
        return False
    clause = _DATA_FIELD_CLAUSE_END.split(preceding)[-1]
    following = _DATA_FIELD_CLAUSE_END.split(text[end + 1 : end + 97], maxsplit=1)[0]
    return bool(_API_COVERAGE_READ.search(clause)) and not _API_COVERAGE_FILE_USE.search(following)


@dataclass(frozen=True)
class ReferenceResolutionResult:
    """Bounded reference records plus explicit extraction accounting."""

    records: list[BundleReference]
    complete: bool
    limitations: tuple[str, ...]
    input_bytes_examined: int
    raw_candidates_considered: int
    accepted_references: int
    runtime_seconds: float
    runtime_seconds_limit: float


_PLAIN_RELATIVE_PATH = re.compile(
    r"(?<![\w:/.-])((?:\./(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+|"
    r"(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,12}))(?![\w/.-])"
)


def _evidence(cleaned_line: str, column: int) -> str:
    """Return a bounded one-line evidence preview."""
    if len(cleaned_line) <= _MAX_EVIDENCE:
        return cleaned_line
    start = max(0, min(column - 1, len(cleaned_line)) - _MAX_EVIDENCE // 2)
    return cleaned_line[start : start + _MAX_EVIDENCE]


@dataclass(frozen=True)
class _ReferenceCandidate:
    raw: str
    start: int
    end: int
    kind: ReferenceKind
    syntax_start: int
    passive_image: bool = False


def _markdown_candidates(
    line: str, *, deadline: float, clock: Callable[[], float], limitations: set[str]
) -> Iterator[_ReferenceCandidate]:
    """Read bounded destinations without splitting spaces or balanced parentheses.

    Explicit reference definitions use the same destination grammar as inline
    links. Recognizing them separately keeps slash-separated prose excluded.
    """
    consumed_until = 0
    for opening in _MARKDOWN_REFERENCE_START.finditer(line):
        # Malformed openings may never yield a candidate. Bound their work too.
        if clock() >= deadline:
            return
        if opening.start() < consumed_until:
            continue
        start = opening.end()
        while start < len(line) and line[start] in " \t":
            start += 1
        if start >= len(line):
            continue
        limit = min(len(line), start + _MAX_MARKDOWN_DESTINATION_CHARS + 2)
        end = start
        if line[start] == "<":
            start += 1
            end = start
            while end < limit and line[end] not in "<>\r\n":
                if line[end] == "\\" and end + 1 < limit:
                    end += 1
                end += 1
            if end - start > _MAX_MARKDOWN_DESTINATION_CHARS:
                limitations.add("markdown_destination")
                continue
            if end >= limit or line[end] != ">":
                continue
            raw = line[start:end]
            destination_end = end + 1
        else:
            depth = 0
            while end < limit and not line[end].isspace():
                char = line[end]
                if char == "\\" and end + 1 < limit:
                    end += 2
                    continue
                if char == "(":
                    depth += 1
                elif char == ")":
                    if depth == 0:
                        break
                    depth -= 1
                elif char in "<>":
                    break
                end += 1
            if end - start > _MAX_MARKDOWN_DESTINATION_CHARS:
                limitations.add("markdown_destination")
                continue
            if depth or end == start:
                continue
            raw = line[start:end]
            destination_end = end
        if opening.group().endswith("("):
            ending = _MARKDOWN_INLINE_END.match(
                line, destination_end, min(len(line), destination_end + 512)
            )
            if ending is None:
                if len(line) - destination_end > 512:
                    limitations.add("markdown_title")
                continue
        else:
            if len(line) - destination_end > 512:
                limitations.add("markdown_title")
                continue
            ending = _MARKDOWN_DEFINITION_END.fullmatch(line, destination_end)
            # A destination can only be followed by a title, not arbitrary prose.
            if ending is None:
                continue
        consumed_until = ending.end()
        is_image = opening.group().startswith("![")
        label = line[opening.start() + 2 : opening.end() - 2] if is_image else ""
        # Retain main's conservative passive-image grammar even when the
        # destination parser can recover a more complex literal filename.
        passive_image = (
            is_image
            and not any(char in label for char in "[]\\")
            and bool(_PASSIVE_IMAGE_DESTINATION.fullmatch(line[opening.end() : consumed_until - 1]))
        )
        yield _ReferenceCandidate(
            _MARKDOWN_STRUCTURAL_ESCAPE.sub(r"\1", raw),
            start,
            consumed_until,
            ReferenceKind.MARKDOWN_IMAGE if is_image else ReferenceKind.MARKDOWN_LINK,
            opening.start(),
            passive_image,
        )


def _pattern_candidates(
    pattern: re.Pattern[str], line: str, kind: ReferenceKind
) -> Iterator[_ReferenceCandidate]:
    for match in pattern.finditer(line):
        yield _ReferenceCandidate(
            match.group(1), match.start(1), match.end(1), kind, match.start(1)
        )


def _advance_inline_code_state(
    line: str,
    end: int,
    cursor: int,
    delimiter_length: int | None,
) -> tuple[int, int | None]:
    """Advance a bounded CommonMark-style backtick-span state to ``end``."""
    while cursor < end:
        if line[cursor] != "`":
            cursor += 1
            continue
        preceding_backslashes = 0
        probe = cursor - 1
        while probe >= 0 and line[probe] == "\\":
            preceding_backslashes += 1
            probe -= 1
        run_end = cursor + 1
        while run_end < end and line[run_end] == "`":
            run_end += 1
        if preceding_backslashes % 2 == 0:
            run_length = run_end - cursor
            if delimiter_length is None:
                delimiter_length = run_length
            elif delimiter_length == run_length:
                delimiter_length = None
        cursor = run_end
    return cursor, delimiter_length


def _is_escaped_marker(line: str, offset: int) -> bool:
    """Return whether the character at ``offset`` has an odd backslash escape."""
    backslashes = 0
    offset -= 1
    while offset >= 0 and line[offset] == "\\":
        backslashes += 1
        offset -= 1
    return backslashes % 2 == 1


def _markdown_block_view(line: str) -> tuple[str, int, bool, int]:
    """Expose fences inside containers without claiming to parse their rendering."""
    expanded = line.expandtabs(4)
    cursor = 0
    quote_depth = 0
    has_list = False
    # More than four spaces after a list marker are content indentation;
    # retain that indentation so a code block cannot become a passive image.
    while match := _MARKDOWN_CONTAINER_PREFIX.match(expanded, cursor):
        quote_depth += int(match.group(1) is not None)
        has_list |= match.group(1) is None
        cursor = match.end()
    return expanded[cursor:], quote_depth, has_list, cursor


def _html_context_end(match: re.Match[str]) -> re.Pattern[str] | None:
    """Recognize literal terminators; other HTML contexts end at a blank line."""
    marker = match.group(0)
    if marker == "<!--":
        return re.compile(r"-->")
    if marker == "<?":
        return re.compile(r"\?>")
    if marker.upper() == "<![CDATA[":
        return re.compile(r"\]\]>")
    if marker.startswith("<!"):
        return re.compile(r">")
    tag = (match.group(1) or "").lower()
    if tag in {"pre", "script", "style", "textarea"}:
        return re.compile(rf"</{tag}\s*>", re.IGNORECASE)
    return None


def _quoted_frontmatter_scalars(
    text: str, *, deadline: float, clock: Callable[[], float]
) -> set[tuple[int, int]]:
    """Locate real quoted YAML scalars, conservatively retaining refs on failure.

    Parse events rather than constructing YAML objects or expanding aliases.
    The optional metadata exemption has bounded input, events, and runtime;
    unsupported/oversized frontmatter keeps normal reference accounting.
    """
    if not text.startswith("---\n") and not text.startswith("---\r\n"):
        return set()
    prefix = text[:_MAX_VERSION_FRONTMATTER_CHARS]
    closing = re.search(r"^---[ \t]*\r?$", prefix[4:], re.MULTILINE)
    if closing is None:
        return set()
    frontmatter = prefix[: closing.start() + 4]
    # Every eligible version field contains this literal; other headers cannot
    # produce an exemption and need no additional YAML parsing.
    if "version" not in frontmatter:
        return set()
    spans: set[tuple[int, int]] = set()
    events = yaml.parse(frontmatter)
    try:
        for count, event in enumerate(events, 1):
            if count >= MAX_RAW_REFERENCE_CANDIDATES or clock() >= deadline:
                return set()
            if (
                isinstance(event, yaml.ScalarEvent)
                and event.style in {"'", '"'}
                and event.start_mark.line == event.end_mark.line
            ):
                # YAML recognizes more line separators than StringIO. Absolute
                # offsets bind the exemption to the same source characters.
                spans.add((event.start_mark.index + 1, event.end_mark.index - 1))
    except yaml.YAMLError:
        return set()
    finally:
        events.close()
    return spans


def _candidate_strings(
    text: str,
    *,
    deadline: float,
    clock: Callable[[], float],
    corroborate_images: bool = False,
) -> tuple[list[tuple[str, int, int, str, ReferenceKind, bool]], tuple[str, ...]]:
    """Extract path-like strings without materializing all matches or lines.

    Each candidate iterator contributes at most one pending match to a small
    merge heap.  This preserves source ordering while ensuring a dense,
    attacker-controlled line cannot be fully enumerated and sorted before the
    candidate and time ceilings are enforced.
    """
    candidates: list[tuple[str, int, int, str, ReferenceKind, bool]] = []
    limitations: set[str] = set()
    seen: set[tuple[int, int, str]] = set()
    active_fence: tuple[str, int, int, int] | None = None
    in_html = False
    html_end: re.Pattern[str] | None = None
    inline_code_delimiter: int | None = None
    quoted_scalars = _quoted_frontmatter_scalars(text, deadline=deadline, clock=clock)
    line_offset = 0
    in_frontmatter = False
    previous_line_blank = True
    source_offset = 0
    for line_number, line in enumerate(StringIO(text), 1):
        if clock() >= deadline:
            return candidates, ("runtime",)
        stripped_line = line.rstrip("\r\n")
        json_version_match = _JSON_VERSION_FIELD.fullmatch(stripped_line)
        xml_version_match = _XML_VERSION_DECLARATION.fullmatch(stripped_line)
        version_match = _FRONTMATTER_VERSION.match(stripped_line) if quoted_scalars else None
        source_offset += len(line)
        following_line_blank = source_offset == len(text) or bool(
            re.match(r"[ \t]{0,3}(?:\r?\n|\Z)", text[source_offset : source_offset + 5])
        )
        line_in_frontmatter = in_frontmatter
        frontmatter_marker = stripped_line.strip(" \t")
        if line_number == 1 and frontmatter_marker.removeprefix("\ufeff").strip(" \t") == "---":
            in_frontmatter = line_in_frontmatter = True
        elif in_frontmatter and frontmatter_marker in {"---", "..."}:
            in_frontmatter = False
        # In GFM, inline code cannot cross Markdown table cell/row boundaries.
        # Do not let an unmatched tick on an earlier row taint the next row.
        if (stripped_line.lstrip().startswith("|")
                and stripped_line.rstrip().endswith("|")
                and active_fence is None and not in_html and not in_frontmatter):
            inline_code_delimiter = None
        line_started_in_inline_code = inline_code_delimiter is not None
        block_line, quote_depth, has_list, prefix_width = _markdown_block_view(stripped_line)
        fence_match = _MARKDOWN_FENCE.fullmatch(block_line)
        line_in_fence = active_fence is not None
        closes_fence = False
        if active_fence is not None and fence_match is not None:
            marker = fence_match.group(1)
            closes_fence = (
                marker[0] == active_fence[0]
                and len(marker) >= active_fence[1]
                and quote_depth == active_fence[2]
                and prefix_width + fence_match.start(1) >= active_fence[3]
                and not has_list
                and not fence_match.group(2).strip(" \t")
            )
        elif active_fence is None and fence_match is not None and not in_html:
            marker = fence_match.group(1)
            required_indent = prefix_width + fence_match.start(1) if has_list else 0
            active_fence = (marker[0], len(marker), quote_depth, required_indent)
            line_in_fence = True
        line_is_indented_code = stripped_line.expandtabs(4).startswith(
            "    "
        ) or block_line.startswith("    ")
        if in_html and html_end is None and not block_line.strip():
            in_html = False
        line_in_html = in_html
        html_search_start = 0
        if not line_in_fence and not line_is_indented_code:
            while True:
                if clock() >= deadline:
                    return candidates, ("runtime",)
                if not in_html:
                    html_start = _HTML_CONTEXT_START.search(block_line, html_search_start)
                    if html_start is None:
                        break
                    in_html = True
                    line_in_html = True
                    html_end = _html_context_end(html_start)
                    html_search_start = html_start.end()
                if html_end is None:
                    break
                html_close = html_end.search(block_line, html_search_start)
                if html_close is None:
                    break
                html_search_start = html_close.end()
                in_html = False
                html_end = None
        cleaned_line = " ".join(line.strip().split())
        declaration = (
            _DOCUMENTATION_IMAGE_DECLARATION.fullmatch(stripped_line)
            if len(stripped_line) <= _MAX_MARKDOWN_DESTINATION_CHARS
            and previous_line_blank
            and following_line_blank
            and not line_in_frontmatter
            and not line_in_fence
            and not line_is_indented_code
            and not line_in_html
            and not line_started_in_inline_code
            and not quote_depth
            and not has_list
            else None
        )
        iterators = [
            _markdown_candidates(line, deadline=deadline, clock=clock, limitations=limitations),
            _pattern_candidates(_INLINE_CODE_COMMAND_PATH, line, ReferenceKind.INLINE_COMMAND),
            _pattern_candidates(_QUOTED_OR_CODE_PATH, line, ReferenceKind.QUOTED_OR_CODE),
            _pattern_candidates(_PLAIN_RELATIVE_PATH, line, ReferenceKind.PLAIN_PATH),
        ]
        pending: list[tuple[int, int, _ReferenceCandidate]] = []
        image_label_spans: list[tuple[int, int, str]] = []
        markdown_destination_span: tuple[int, int] | None = None
        inline_code_cursor = 0
        for pattern_index, iterator in enumerate(iterators):
            match = next(iterator, None)
            if match is not None:
                heapq.heappush(pending, (match.syntax_start, pattern_index, match))
            if clock() >= deadline:
                return candidates, ("runtime",)
        while pending:
            if clock() >= deadline:
                return candidates, ("runtime",)
            sort_start, pattern_index, match = heapq.heappop(pending)
            reference_kind = match.kind
            if (
                reference_kind is ReferenceKind.QUOTED_OR_CODE
                and declaration is not None
                and match.start == declaration.start(1)
                and match.end == declaration.end(1)
                and match.raw == declaration.group(1)
            ):
                reference_kind = ReferenceKind.DOCUMENTATION_IMAGE
            if not line_in_fence and not line_is_indented_code and not line_in_html:
                inline_code_cursor, inline_code_delimiter = _advance_inline_code_state(
                    line, sort_start, inline_code_cursor, inline_code_delimiter
                )
            if reference_kind is ReferenceKind.MARKDOWN_IMAGE:
                if (
                    (corroborate_images and line_in_frontmatter)
                    or line_in_fence
                    or line_is_indented_code
                    or line_in_html
                    or inline_code_delimiter is not None
                    or not match.passive_image
                ):
                    reference_kind = ReferenceKind.QUOTED_OR_CODE
                elif _is_escaped_marker(line, match.syntax_start):
                    reference_kind = ReferenceKind.PLAIN_PATH
            raw = match.raw
            if reference_kind is ReferenceKind.MARKDOWN_IMAGE:
                # Same-target image alt text is redundant; different visible
                # targets and command operands still require their own records.
                image_label_spans.append((match.syntax_start, match.start, raw))
            redundant_image_label = reference_kind is ReferenceKind.PLAIN_PATH and any(
                start <= match.start < end and raw == destination
                for start, end, destination in image_label_spans
            )
            # Markdown candidates sort at their opening marker so their labels
            # can be classified. Suppress only destination/title text, not an
            # independent artifact named in a visible link or image label.
            inside_destination = (
                pattern_index != 0
                and markdown_destination_span is not None
                and markdown_destination_span[0] <= match.start < markdown_destination_span[1]
            )
            if pattern_index == 0:
                markdown_destination_span = (match.start, match.end)
            # Only the quoted scalar of a frontmatter version field is metadata.
            # Numeric filenames elsewhere (including explicit Markdown links)
            # must retain normal missing/resolved reference accounting.
            is_version_metadata = (
                reference_kind is ReferenceKind.QUOTED_OR_CODE
                and version_match is not None
                and (match.start, match.end) == version_match.span("version")
                and (line_offset + match.start, line_offset + match.end) in quoted_scalars
            )
            is_json_version_metadata = (
                reference_kind is ReferenceKind.QUOTED_OR_CODE
                and json_version_match is not None
                and (match.start, match.end) == json_version_match.span("version")
            )
            is_xml_version_metadata = (
                reference_kind is ReferenceKind.QUOTED_OR_CODE
                and xml_version_match is not None
                and (match.start, match.end) == xml_version_match.span("version")
            )
            if (
                not inside_destination
                and not redundant_image_label
                and not is_version_metadata
                and not is_json_version_metadata
                and not is_xml_version_metadata
            ):
                key = (line_number, match.start, raw)
                if key not in seen:
                    seen.add(key)
                    candidates.append(
                        (
                            raw,
                            line_number,
                            match.start + 1,
                            _evidence(cleaned_line, match.start + 1),
                            reference_kind,
                            reference_kind is ReferenceKind.QUOTED_OR_CODE
                            and not line_in_frontmatter
                            and not line_in_fence
                            and not line_is_indented_code
                            and not line_in_html
                            and inline_code_delimiter == 1
                            and (
                                _is_documented_data_field(
                                    text, line_offset + match.start, line_offset + match.end
                                )
                                or _is_documented_schema_table_field(
                                    text, line_offset + match.start, line_offset + match.end
                                )
                                or _is_documented_url_hostname(
                                    text, line_offset + match.start, line_offset + match.end
                                )
                                or _is_documented_address_or_version(
                                    text, line_offset + match.start, line_offset + match.end
                                )
                                or _is_documented_api_coverage_field(
                                    text, line_offset + match.start, line_offset + match.end
                                )
                            ),
                        )
                    )
                    if len(candidates) >= MAX_RAW_REFERENCE_CANDIDATES:
                        return candidates, ("raw_candidates",)
            next_match = next(iterators[pattern_index], None)
            if next_match is not None:
                heapq.heappush(pending, (next_match.syntax_start, pattern_index, next_match))
        if not line_in_fence and not line_is_indented_code and not line_in_html:
            _, inline_code_delimiter = _advance_inline_code_state(
                line,
                len(line),
                inline_code_cursor,
                inline_code_delimiter,
            )
        if closes_fence:
            active_fence = None
        line_offset += len(line)
        previous_line_blank = not stripped_line.strip()
    return candidates, tuple(sorted(limitations))


def _normalize_candidate(raw: str, source_path: str) -> str | None:
    """Return a contained relative POSIX candidate, or None when unsupported."""
    raw = raw.strip()
    split = urlsplit(raw)
    if split.scheme or split.netloc or raw.startswith(("/", "\\", "#")):
        return None
    # Split URI syntax before decoding so %23/%3F remain filename characters.
    # Decode exactly once, then apply containment checks to the decoded path.
    path_part = unquote(split.path).replace("\\", "/")
    if not path_part or path_part.startswith("/"):
        return None
    if len(path_part) >= 2 and path_part[1] == ":":
        return None
    source_parent = PurePosixPath(source_path).parent.as_posix()
    joined = posixpath.normpath(posixpath.join(source_parent, path_part))
    if joined in {"", ".", ".."} or joined.startswith("../"):
        return None
    return joined.removeprefix("./")


def _escapes_bundle_root(raw: str, source_path: str) -> bool:
    """Detect a relative link that lexically escapes the inspected bundle.

    Remote URLs and fragments are not local file dependencies. Decode once,
    matching the normal resolver, without probing the external filesystem.
    """
    # urlsplit treats a local Windows drive as a URL scheme. Such a path
    # cannot belong to the acquired bundle and is not a remote documentation URL.
    if re.match(r"^[A-Za-z]:", raw.strip()):
        return True
    split = urlsplit(raw.strip())
    # file: identifies a local resource outside our acquired inventory.
    # No filesystem access is needed to treat it as uninspected.
    if split.scheme.lower() == "file":
        return bool(split.path or split.netloc)
    if split.scheme or split.netloc:
        return False
    path_part = unquote(split.path).replace("\\", "/")
    if not path_part:
        return False
    # Encoded absolute and drive-prefixed local files are outside the bundle.
    # Ordinary site-root Markdown links remain out of scope.
    if path_part.startswith("/"):
        return not split.path.startswith("/")
    if len(path_part) >= 2 and path_part[1] == ":":
        return True
    joined = posixpath.normpath(
        posixpath.join(PurePosixPath(source_path).parent.as_posix(), path_part)
    )
    return joined == ".." or joined.startswith("../")


def documentation_image_provenance(
    source_path: str,
    source_bytes: bytes,
    *,
    deadline: float,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[str, frozenset[tuple[int, int, str, str]]] | None:
    """Reconstruct passive image identities from bounded canonical source bytes.

    No filesystem reads or basename inference are performed. A truncated source
    or extraction cannot establish that all uses of an asset were observed.
    Callers cache this result per source and share an aggregate time/byte budget.
    """
    if len(source_bytes) > MAX_REFERENCE_SOURCE_BYTES or clock() >= deadline:
        return None
    try:
        source = source_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    candidates, limitations = _candidate_strings(
        source, deadline=deadline, clock=clock, corroborate_images=True
    )
    if limitations or clock() >= deadline:
        return None
    identities = set()
    non_passive_targets: set[str] = set()
    non_passive_basenames: set[str] = set()
    for raw, line, column, _evidence_text, kind, _is_data_field in candidates:
        target = _normalize_candidate(raw, source_path)
        if kind in {ReferenceKind.DOCUMENTATION_IMAGE, ReferenceKind.MARKDOWN_IMAGE}:
            if target is not None:
                identities.add((line, column, target, str(kind)))
        elif target is not None:
            non_passive_targets.add(target)
            if "/" not in unquote(raw).replace("\\", "/"):
                # The public resolver may resolve a unique basename elsewhere
                # in the inventory. Do not let a missing/altered public record
                # hide that independent ambiguous or executable use.
                non_passive_basenames.add(PurePosixPath(target).name)
    return hashlib.sha256(source_bytes).hexdigest(), frozenset(
        identity
        for identity in identities
        if identity[2] not in non_passive_targets
        and PurePosixPath(identity[2]).name not in non_passive_basenames
    )


def resolve_bundle_references_with_metadata(
    skill_dir: Path,
    *,
    source_path: str,
    source_text: str,
    known_paths: list[str],
    clock: Callable[[], float] = time.monotonic,
    deadline: float | None = None,
) -> ReferenceResolutionResult:
    """Resolve references with separate deterministic input/work/output bounds."""
    started_at = clock()
    local_deadline = started_at + MAX_REFERENCE_RUNTIME_SECONDS
    effective_deadline = local_deadline if deadline is None else min(local_deadline, deadline)
    runtime_limit = max(0.0, effective_deadline - started_at)
    if clock() >= effective_deadline:
        return ReferenceResolutionResult(
            records=[],
            complete=False,
            limitations=("runtime",),
            input_bytes_examined=0,
            raw_candidates_considered=0,
            accepted_references=0,
            runtime_seconds=max(0.0, clock() - started_at),
            runtime_seconds_limit=runtime_limit,
        )
    # UTF-8 always uses at least one byte per code point, so this character
    # prefix is sufficient to determine whether the byte limit was crossed
    # without first encoding an unbounded compatibility-wrapper input.
    source_prefix = source_text[: MAX_REFERENCE_SOURCE_BYTES + 1]
    encoded_prefix = source_prefix.encode("utf-8")
    input_limited = (
        len(source_text) > MAX_REFERENCE_SOURCE_BYTES
        or len(encoded_prefix) > MAX_REFERENCE_SOURCE_BYTES
    )
    bounded_source = encoded_prefix[:MAX_REFERENCE_SOURCE_BYTES].decode("utf-8", errors="ignore")
    input_bytes_examined = min(len(encoded_prefix), MAX_REFERENCE_SOURCE_BYTES)

    known = set(known_paths)
    basename_index: dict[str, list[str]] = {}
    for path in sorted(known):
        basename_index.setdefault(PurePosixPath(path).name, []).append(path)

    candidates, candidate_limitations = _candidate_strings(
        bounded_source,
        deadline=effective_deadline,
        clock=clock,
    )
    limitations = ["input_bytes"] if input_limited else []
    limitations.extend(candidate_limitations)
    records: list[BundleReference] = []
    source_sha256: str | None = None
    accepted_keys: set[tuple[str, str]] = set()
    for raw, line, column, evidence, reference_kind, is_data_field in candidates:
        if clock() > effective_deadline:
            limitations.append("runtime")
            break
        target = _normalize_candidate(raw, source_path)
        status = "rejected"
        # Rejected local parent traversal is an *uninspected dependency*,
        # not a completed scan. Preserve the public rejected status.
        disposition = (
            ArtifactDisposition.PARTIAL
            if reference_kind in {ReferenceKind.MARKDOWN_LINK, ReferenceKind.INLINE_COMMAND}
            and target is None
            and _escapes_bundle_root(raw, source_path)
            else ArtifactDisposition.OUT_OF_SCOPE
        )
        resolved_target: str | None = None
        if target is not None:
            # Resolution is intentionally confined to the caller's already
            # bounded discovery inventory. Re-probing the filesystem here
            # could reintroduce a path omitted by an artifact, depth, or
            # runtime limit and silently expand analyzer work past that bound.
            if target in known:
                resolved_target = target
                status = "resolved"
                disposition = ArtifactDisposition.ANALYZED
            elif "/" not in unquote(raw).replace("\\", "/"):
                matches = basename_index.get(PurePosixPath(target).name, [])
                if len(matches) == 1:
                    resolved_target = matches[0]
                    status = "resolved"
                    disposition = ArtifactDisposition.ANALYZED
                elif len(matches) > 1:
                    status = "ambiguous"
                    disposition = ArtifactDisposition.PARTIAL
                else:
                    status = "missing"
                    disposition = ArtifactDisposition.PARTIAL
            else:
                status = "missing"
                disposition = ArtifactDisposition.PARTIAL
        # Real inventory matches (including ambiguity) always take precedence
        # over prose. An independent file use of the same token stays a record.
        if status == "missing" and is_data_field:
            continue
        if status != "rejected":
            accepted_key = (status, resolved_target or target or raw)
            if accepted_key not in accepted_keys:
                if len(accepted_keys) >= MAX_ACCEPTED_REFERENCES:
                    limitations.append("accepted_references")
                    break
                accepted_keys.add(accepted_key)
        if len(records) >= MAX_REFERENCE_RECORDS:
            limitations.append("output_records")
            break
        records.append(
            {
                "source_path": source_path,
                "line": line,
                "column": column,
                "evidence": evidence,
                "target_path": resolved_target,
                "status": status,
                "disposition": disposition,
                "reference_kind": reference_kind,
            }
        )
        needs_provenance = reference_kind is ReferenceKind.DOCUMENTATION_IMAGE or (
            reference_kind is ReferenceKind.MARKDOWN_IMAGE
            and resolved_target is not None
            and PurePosixPath(resolved_target).suffix.lower() in {".jpg", ".jpeg"}
        )
        if needs_provenance and not input_limited:
            if source_sha256 is None:
                source_sha256 = hashlib.sha256(encoded_prefix).hexdigest()
            records[-1]["source_sha256"] = source_sha256
    stable_limitations = tuple(dict.fromkeys(limitations))
    runtime_seconds = max(0.0, clock() - started_at)
    if runtime_seconds >= runtime_limit and "runtime" not in stable_limitations:
        stable_limitations = (*stable_limitations, "runtime")
    return ReferenceResolutionResult(
        records=records,
        complete=not stable_limitations,
        limitations=stable_limitations,
        input_bytes_examined=input_bytes_examined,
        raw_candidates_considered=len(candidates),
        accepted_references=len(accepted_keys),
        runtime_seconds=runtime_seconds,
        runtime_seconds_limit=runtime_limit,
    )


def resolve_bundle_references(
    skill_dir: Path,
    *,
    source_path: str,
    source_text: str,
    known_paths: list[str],
    clock: Callable[[], float] = time.monotonic,
    deadline: float | None = None,
) -> list[BundleReference]:
    """Compatibility wrapper returning bounded reference records."""
    return resolve_bundle_references_with_metadata(
        skill_dir,
        source_path=source_path,
        source_text=source_text,
        known_paths=known_paths,
        clock=clock,
        deadline=deadline,
    ).records
