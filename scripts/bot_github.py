# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""GitHub reads and writes shared by the select, apply and report scripts.

Kept apart from the selection and review logic so that the rules
stay readable without API plumbing interleaved through them.
Nothing here decides whether an action is permitted; callers do
that first.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from typing import Any, cast

API_VERSION = "2026-03-10"
# gh ends its message with the status in one of two forms: after the
# message of a JSON reply, "gh: Not Found (HTTP 404)", or alone for any
# other reply, such as an XML error from artifact storage, "gh: HTTP
# 403". Each alternative is a whole form that ends a line, and the last
# match wins, so neither a hybrid nor a status quoted earlier counts.
STATUS_RE = re.compile(r"\(HTTP (\d{3})\)$|^gh: HTTP (\d{3})$", re.MULTILINE)
ABSENT = frozenset({404, 410})
TIMEOUT_SECONDS = 60
TRANSIENT = frozenset({500, 502, 503, 504})
READ_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 2
SHA_RE = re.compile(r"[0-9a-f]{40}")
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$")


def parse_status(text: str) -> int | None:
    """The HTTP status gh appends to ``text``, in either of its forms."""
    matches = STATUS_RE.findall(text)
    if not matches:
        return None
    json_form, bare_form = matches[-1]
    return int(json_form or bare_form)


class GitHubError(Exception):
    """A call to GitHub failed.

    Carries the HTTP status where gh reported one, so callers can
    tell an endpoint that is absent from one that is briefly
    unreachable.
    """

    def __init__(self, message: str, status: int | None = None) -> None:
        """Record the message and the status given, or else gh's."""
        super().__init__(message)
        self.status: int | None = (
            status if status is not None else parse_status(message)
        )


def is_read(args: list[str]) -> bool:
    """Whether a gh invocation only reads, and so is safe to repeat.

    GraphQL goes through one endpoint for queries and mutations alike,
    so no GraphQL call counts as a read here unless the caller says so.
    """
    if args[:1] == ["api"]:
        return args[1:2] != ["graphql"] and "--method" not in args
    return args[:2] in (["pr", "list"], ["pr", "view"], ["search", "prs"])


def run_once(args: list[str], input: str | None) -> str:
    """One gh invocation, raising GitHubError on any failure."""
    try:
        proc = subprocess.run(
            ["gh", *args],
            input=input,
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitHubError(f"gh timed out after {TIMEOUT_SECONDS} seconds") from exc
    except OSError as exc:
        raise GitHubError(f"could not run gh: {exc}") from exc
    if proc.returncode != 0:
        raise GitHubError(proc.stderr.strip() or f"gh {' '.join(args)} failed")
    return proc.stdout


def run_gh(
    args: list[str], *, input: str | None = None, read: bool | None = None
) -> str:
    """Run gh with a pinned REST API version, returning stdout or raising.

    Reads retry a transient 5xx or timeout with a short backoff: a
    selection makes many reads, and one 502 should not cost the run.
    Writes run once; a repeated review submission is not harmless.
    ``read`` overrides the guess from the arguments, for a GraphQL
    query the caller knows to be read-only.
    """
    if args[:1] == ["api"] and args[1:2] != ["graphql"]:
        args = [*args, "--header", f"X-GitHub-Api-Version: {API_VERSION}"]
    repeatable = is_read(args) if read is None else read
    attempts = READ_ATTEMPTS if repeatable else 1
    for attempt in range(1, attempts + 1):
        try:
            return run_once(args, input)
        except GitHubError as exc:
            transient = exc.status in TRANSIENT or "timed out" in str(exc)
            if attempt == attempts or not transient:
                raise
            time.sleep(RETRY_DELAY_SECONDS * attempt)
    raise AssertionError("unreachable")  # pragma: no cover


def decode_response(raw: str) -> Any:
    """Keep malformed API responses on the operational-failure path."""
    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise GitHubError(f"invalid JSON from GitHub: {exc}") from exc


def api_object(endpoint: str) -> dict[str, Any]:
    """Read one endpoint that returns a JSON object."""
    parsed = decode_response(run_gh(["api", endpoint]))
    if not isinstance(parsed, dict):
        raise GitHubError(f"expected an object from {endpoint}")
    return cast("dict[str, Any]", parsed)


def api_list(endpoint: str) -> list[dict[str, Any]]:
    """Read every page, refusing incomplete or non-list responses."""
    raw = run_gh(["api", endpoint, "--paginate", "--slurp"])
    pages = decode_response(raw)
    if not isinstance(pages, list):
        raise GitHubError(f"expected paginated arrays from {endpoint}")
    entries: list[dict[str, Any]] = []
    for page in cast("list[Any]", pages):
        if not isinstance(page, list):
            raise GitHubError(f"expected an array page from {endpoint}")
        for entry in cast("list[Any]", page):
            if not isinstance(entry, dict):
                raise GitHubError(f"expected an object entry from {endpoint}")
            entries.append(cast("dict[str, Any]", entry))
    return entries


def api_write(method: str, endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Send a JSON body with the given method and return the object reply."""
    raw = run_gh(
        ["api", "--method", method, endpoint, "--input", "-"],
        input=json.dumps(payload),
    )
    parsed: Any = decode_response(raw) if raw.strip() else {}
    if not isinstance(parsed, dict):
        raise GitHubError(f"expected an object from {method} {endpoint}")
    return cast("dict[str, Any]", parsed)


def graphql(
    query: str, variables: dict[str, Any], *, read: bool = False
) -> dict[str, Any]:
    """Run one GraphQL operation, surfacing any error entry as a failure.

    gh exits non-zero when the response carries ``errors``, and the
    message lands on stderr; a partial ``data`` payload is never
    returned to the caller as if it were complete. Operations run once
    unless the caller passes ``read=True`` for a query with no side
    effects, which then retries transient failures like a REST read.
    """
    raw = run_gh(
        ["api", "graphql", "--input", "-"],
        input=json.dumps({"query": query, "variables": variables}),
        read=read,
    )
    parsed = decode_response(raw)
    if not isinstance(parsed, dict):
        raise GitHubError("expected an object from GraphQL")
    reply = cast("dict[str, Any]", parsed)
    if reply.get("errors"):
        raise GitHubError(f"GraphQL errors: {json.dumps(reply['errors'])[:2000]}")
    data = reply.get("data")
    if not isinstance(data, dict):
        raise GitHubError("GraphQL reply carried no data object")
    return cast("dict[str, Any]", data)


def is_absent(exc: GitHubError) -> bool:
    """Whether a failure means the resource does not exist."""
    return exc.status in ABSENT


def require_str(data: dict[str, Any], key: str, context: str) -> str:
    """Return a non-empty string field or fail the operation."""
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise GitHubError(f"{context}: missing or invalid {key!r}")
    return value


def require_int(data: dict[str, Any], key: str, context: str) -> int:
    """Return a positive integer field or fail the operation."""
    value = data.get(key)
    if type(value) is not int or value <= 0:
        raise GitHubError(f"{context}: missing or invalid {key!r}")
    return value


def require_sha(data: dict[str, Any], key: str, context: str) -> str:
    """Return a 40-hex commit SHA field or fail the operation."""
    value = require_str(data, key, context)
    if not SHA_RE.fullmatch(value):
        raise GitHubError(f"{context}: {key!r} is not a commit SHA")
    return value


def safe_message(exc: BaseException) -> str:
    """Render an error for a log that workflow commands are parsed from."""
    return ascii(str(exc)).replace("::", ": :").replace("##[", "# #[")
