# /// script
# requires-python = ">=3.10"
# dependencies = ["requests", "rich"]
# ///
# Copyright 2026 Cloudsmith Ltd

"""Assay: OSV vulnerability summaries for Cloudsmith workspaces and repositories."""

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests
from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

__version__ = "2.0.0"

# --- Configuration ---
BASE_API = os.environ.get("CLOUDSMITH_API_HOST", "https://api.cloudsmith.io").rstrip("/")
PAGE_SIZE = 500  # max items per page on the v2 API
REQUEST_TIMEOUT = 60

# Ordered most to least severe; drives sorting, columns and bars
SEVERITIES = ("malware", "critical", "high", "medium", "low", "unknown")
SEVERITY_LABELS = {
    "malware": "Malware",
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "unknown": "Unknown",
}
SEVERITY_SHORT = {
    "malware": "Mal",
    "critical": "Crit",
    "high": "High",
    "medium": "Med",
    "low": "Low",
    "unknown": "Unk",
}
SEVERITY_STYLES = {
    "malware": "bright_magenta",
    "critical": "red1",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "dodger_blue1",
    "unknown": "grey58",
}

# stderr console for progress/status, stdout stays clean for json output
stderr_console = Console(stderr=True)
stdout_console = Console()


class AuthError(Exception):
    """Raised when no usable Cloudsmith credential can be resolved."""


class ApiError(Exception):
    """Raised when the Cloudsmith API returns a non-200 response."""

    def __init__(self, status_code, detail):
        super().__init__(f"{status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


def get_args(argv=None):
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="assay",
        description=(
            "Assay: OSV vulnerability summaries for Cloudsmith workspaces "
            "and repositories."
        ),
    )
    parser.add_argument(
        "-w",
        "--workspace",
        "-o",
        "--owner",
        dest="workspace",
        required=True,
        help="Workspace (organization/owner) slug on Cloudsmith.",
    )
    parser.add_argument(
        "-r",
        "--repo",
        help="Repository slug. Omit for a workspace-wide summary.",
    )
    parser.add_argument(
        "-F",
        "--output",
        choices=["table", "json"],
        default="table",
        help="Output format: 'table' (default) or 'json'.",
    )
    parser.add_argument(
        "--sort",
        choices=["severity", "total", "name", "downloads", "uploaded"],
        default="severity",
        help=(
            "Package sort order. 'severity' (default) ranks by malware, then "
            "critical, high, medium, low and unknown counts."
        ),
    )
    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        metavar="N",
        help=(
            "Only show the top N packages (0 = all). Defaults to 5 for "
            "workspace tables, otherwise all."
        ),
    )

    filters = parser.add_argument_group("filters (applied by the API)")
    filters.add_argument(
        "--threat-level",
        choices=list(SEVERITIES),
        help="Only include packages with findings in this severity bucket.",
    )
    filters.add_argument(
        "--vulnerability-id",
        metavar="ID",
        help=(
            "Only include packages affected by this advisory, e.g. "
            "CVE-2024-1234 or GHSA-xxxx. Also matches aliases."
        ),
    )
    malware = filters.add_mutually_exclusive_group()
    malware.add_argument(
        "--malware-only",
        dest="is_malware",
        action="store_const",
        const=True,
        help="Only include malware advisories (MAL- prefix or CWE-506).",
    )
    malware.add_argument(
        "--exclude-malware",
        dest="is_malware",
        action="store_const",
        const=False,
        help="Exclude malware advisories.",
    )

    auth = parser.add_argument_group("authentication")
    auth.add_argument(
        "--auth",
        choices=["auto", "env", "cli"],
        default="auto",
        help=(
            "Credential source. 'auto' (default) uses CLOUDSMITH_API_KEY if "
            "set, otherwise the Cloudsmith CLI."
        ),
    )
    auth.add_argument(
        "-P",
        "--profile",
        help="Cloudsmith CLI profile to use (implies --auth cli).",
    )

    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    args = parser.parse_args(argv)
    if args.limit is None:
        # Workspace tables lead with repo stats, so only highlight the worst few
        args.limit = 5 if not args.repo and args.output == "table" else 0
    elif args.limit < 0:
        parser.error("--limit must be 0 or greater")
    if args.profile and args.auth == "auto":
        args.auth = "cli"
    return args


# --- Authentication ---


def credential_from_env():
    """Return the API key from CLOUDSMITH_API_KEY, if set."""
    key = os.environ.get("CLOUDSMITH_API_KEY", "").strip()
    return key or None


def credential_from_cli(workspace, profile=None):
    """Resolve a credential through the Cloudsmith CLI's provider chain.

    Uses `cloudsmith credential-helper generic`, which honours the CLI's
    credentials.ini profiles, SSO sessions and OIDC detection, and prints
    {"version": 1, "username": "token", "password": "<token>"}.
    """
    cli = shutil.which("cloudsmith")
    if not cli:
        raise AuthError(
            "The Cloudsmith CLI was not found on PATH. Install it "
            "(https://docs.cloudsmith.com/developer-tools/cli) or set "
            "CLOUDSMITH_API_KEY."
        )

    cmd = [cli, "credential-helper", "generic", "--workspace", workspace]
    if profile:
        cmd += ["--profile", profile]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=REQUEST_TIMEOUT
        )
    except subprocess.TimeoutExpired as e:
        raise AuthError("Timed out waiting for the Cloudsmith CLI.") from e

    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        if "No such command" in stderr:
            raise AuthError(
                "This version of the Cloudsmith CLI has no credential helper. "
                "Upgrade it with `cloudsmith update`, or set CLOUDSMITH_API_KEY."
            )
        hint = f" ({stderr.splitlines()[-1]})" if stderr else ""
        raise AuthError(
            "The Cloudsmith CLI could not resolve a credential"
            f"{hint}. Sign in with `cloudsmith auth -o {workspace}` or "
            "configure an API key in credentials.ini."
        )

    try:
        token = json.loads(proc.stdout).get("password", "").strip()
    except (ValueError, AttributeError) as e:
        raise AuthError("Unexpected output from the Cloudsmith CLI.") from e
    if not token:
        raise AuthError("The Cloudsmith CLI returned an empty credential.")
    return token


def resolve_credential(args):
    """Return (token, source_description) according to --auth."""
    if args.auth in ("auto", "env"):
        token = credential_from_env()
        if token:
            return token, "CLOUDSMITH_API_KEY"
        if args.auth == "env":
            raise AuthError("CLOUDSMITH_API_KEY environment variable is not set.")

    token = credential_from_cli(args.workspace, args.profile)
    source = "Cloudsmith CLI"
    if args.profile:
        source += f" (profile: {args.profile})"
    return token, source


# --- API ---


def make_session(token):
    """Return a requests session with auth and cache-busting headers."""
    session = requests.Session()
    session.headers.update({
        "Accept": "application/json",
        # Bearer is accepted for API keys as well as SSO/OIDC access tokens
        "Authorization": f"Bearer {token}",
        "User-Agent": f"assay/{__version__}",
        "Cache-Control": "no-cache, no-store",
        "Pragma": "no-cache",
    })
    return session


def _error_detail(response):
    """Extract a readable error message from an API response."""
    try:
        body = response.json()
        if isinstance(body, dict):
            return body.get("detail") or body.get("message") or json.dumps(body)
    except ValueError:
        pass
    return response.text.strip() or response.reason


def fetch_paginated(session, url, params, progress, task):
    """Fetch all pages from a v2 paginated endpoint, returning a flat list.

    Pages are walked using the X-Pagination-PageTotal header, falling back
    to stopping on a short page if the header is absent.
    """
    all_results = []
    page = 1

    while True:
        response = session.get(
            url,
            params={**params, "page": page, "page_size": PAGE_SIZE},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code != 200:
            raise ApiError(response.status_code, _error_detail(response))

        results = response.json().get("results", [])
        all_results.extend(results)

        page_total = int(response.headers.get("X-Pagination-PageTotal") or 0)
        progress.update(
            task,
            description=(
                f"[cyan]Fetched page {page}"
                + (f"/{page_total}" if page_total else "")
                + f" · {len(all_results):,} packages"
            ),
        )

        if page_total:
            if page >= page_total:
                break
        elif len(results) < PAGE_SIZE:
            break
        page += 1

    return all_results


def api_filters(args):
    """Build the server-side filter query params from CLI args."""
    params = {}
    if args.threat_level:
        params["threat_level"] = args.threat_level
    if args.vulnerability_id:
        params["vulnerability_id"] = args.vulnerability_id
    if args.is_malware is not None:
        params["is_malware"] = "true" if args.is_malware else "false"
    return params


def fetch_packages(session, args, log):
    """Fetch vulnerability summaries for the requested scope.

    If the repo-level endpoint is forbidden for the caller, fall back to
    the workspace endpoint filtered to the repository.
    """
    workspace, repo = args.workspace, args.repo
    params = api_filters(args)
    workspace_url = f"{BASE_API}/v2/workspaces/{workspace}/vulnerabilities/packages/"

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
        console=log,
    ) as progress:
        task = progress.add_task("[cyan]Connecting to Cloudsmith API...", total=None)

        if not repo:
            return fetch_paginated(session, workspace_url, params, progress, task)

        repo_url = (
            f"{BASE_API}/v2/workspaces/{workspace}/repos/{repo}"
            "/vulnerabilities/packages/"
        )
        try:
            return fetch_paginated(session, repo_url, params, progress, task)
        except ApiError as e:
            if e.status_code != 403:
                raise
            progress.console.print(
                "  [yellow]![/] Repository endpoint not permitted; "
                "filtering workspace results instead"
            )

        packages = fetch_paginated(session, workspace_url, params, progress, task)
        return [
            p for p in packages
            if p.get("repository") in (f"{workspace}/{repo}", repo)
        ]


# --- Report building ---


def normalise_package(raw):
    """Flatten an API package summary into the report's package shape."""
    counts = raw.get("vulnerability_counts") or {}
    vulns = {s: int(counts.get(s) or 0) for s in SEVERITIES}
    total = int(counts.get("total") or sum(vulns.values()))
    repository = raw.get("repository") or ""

    return {
        "package": raw.get("name", "unknown"),
        "version": raw.get("version", ""),
        "slug_perm": raw.get("slug_perm"),
        "repository": repository.split("/", 1)[-1],
        "format": raw.get("format", ""),
        "downloads": raw.get("downloads", 0),
        "uploaded_at": raw.get("uploaded_at"),
        "sync_status": raw.get("status"),
        "status": "vulnerable" if total else "no_issues_found",
        "highest_severity": next((s for s in SEVERITIES if vulns[s]), None),
        "num_vulnerabilities": total,
        "vulnerabilities": vulns,
    }


def severity_key(item):
    """Sort key ranking most severe first (malware, critical, ... total)."""
    v = item["vulnerabilities"]
    return tuple(-v[s] for s in SEVERITIES) + (-item["num_vulnerabilities"],)


SORT_KEYS = {
    "severity": severity_key,
    "total": lambda p: (-p["num_vulnerabilities"],) + severity_key(p),
    "name": lambda p: (p["package"].lower(), p["version"]),
    "downloads": lambda p: (-(p["downloads"] or 0),) + severity_key(p),
    "uploaded": lambda p: p["uploaded_at"] or "",
}


def sum_counts(packages):
    """Sum severity counts across packages."""
    totals = {s: 0 for s in SEVERITIES}
    for pkg in packages:
        for s in SEVERITIES:
            totals[s] += pkg["vulnerabilities"][s]
    totals["total"] = sum(p["num_vulnerabilities"] for p in packages)
    return totals


def summarise_repositories(packages):
    """Aggregate per-repository totals, most severe first."""
    by_repo = {}
    for pkg in packages:
        by_repo.setdefault(pkg["repository"], []).append(pkg)

    repos = []
    for name, pkgs in by_repo.items():
        totals = sum_counts(pkgs)
        repos.append({
            "repository": name,
            "packages": len(pkgs),
            "num_vulnerabilities": totals.pop("total"),
            "vulnerabilities": totals,
        })
    repos.sort(key=severity_key)
    return repos


def build_report(args, raw_packages):
    """Build the JSON-serialisable report from raw API results."""
    packages = [normalise_package(p) for p in raw_packages]
    packages.sort(key=SORT_KEYS[args.sort], reverse=args.sort == "uploaded")

    totals = sum_counts(packages)
    affected_by = {
        s: sum(1 for p in packages if p["vulnerabilities"][s]) for s in SEVERITIES
    }
    repositories = summarise_repositories(packages)
    shown = packages[: args.limit] if args.limit else packages

    data = {
        "owner": args.workspace,
        "workspace": args.workspace,
        "repository": args.repo,
        "scope": "repository" if args.repo else "workspace",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "filters": api_filters(args),
        "summary": {
            "packages": len(packages),
            "repositories": len(repositories),
            "vulnerabilities": totals,
            "packages_affected_by": affected_by,
        },
        "packages": shown,
    }
    if not args.repo:
        data["repositories"] = repositories
    return {"data": data}


# --- Rich rendering ---


def short_version(version, width=14):
    """Shorten digest-style versions (e.g. docker sha256) for display."""
    if re.fullmatch(r"[0-9a-f]{40,}", version or ""):
        return version[: width - 2] + "…"
    if len(version) > width:
        return version[: width - 1] + "…"
    return version


def count_cell(value, severity):
    """Render a severity count, dimming zeros."""
    if not value:
        return Text("·", style="grey30")
    return Text(f"{value:,}", style=SEVERITY_STYLES[severity])


def severity_bar(counts, width, scale_total=None):
    """Render a stacked, proportional severity bar.

    With `scale_total`, the bar's length is scaled against that total
    (square-root, so small rows stay visible next to very large ones).
    Every non-zero severity gets at least one cell so small counts of
    serious findings stay visible.
    """
    total = sum(counts[s] for s in SEVERITIES)
    if not total:
        return Text("─" * width, style="grey30")

    full_width = width
    if scale_total:
        width = max(1, round(width * math.sqrt(min(total / scale_total, 1))))
        width = max(width, sum(1 for s in SEVERITIES if counts[s]))
        width = min(width, full_width)

    exact = {s: counts[s] * width / total for s in SEVERITIES}
    cells = {s: max(int(exact[s]), 1 if counts[s] else 0) for s in SEVERITIES}

    # Reconcile rounding so the bar is exactly `width` cells wide
    diff = width - sum(cells.values())
    by_remainder = sorted(SEVERITIES, key=lambda s: exact[s] - int(exact[s]), reverse=True)
    while diff > 0:
        for s in by_remainder:
            if diff and counts[s]:
                cells[s] += 1
                diff -= 1
    while diff < 0:
        largest = max(SEVERITIES, key=lambda s: cells[s])
        cells[largest] -= 1
        diff += 1

    bar = Text()
    for s in SEVERITIES:
        bar.append("█" * cells[s], style=SEVERITY_STYLES[s])
    bar.append(" " * (full_width - width))
    return bar


def render_header(data, auth_source):
    """Title panel naming the scope of the report."""
    title = Text()
    title.append("Assay", style="bold bright_cyan")
    title.append("  OSV vulnerability summary", style="bold")

    scope = Text()
    scope.append("Workspace ", style="dim")
    scope.append(data["workspace"], style="cyan")
    scope.append("   Repository ", style="dim")
    if data["repository"]:
        scope.append(data["repository"], style="cyan")
    else:
        scope.append(f"all ({data['summary']['repositories']})", style="cyan")

    meta = Text(style="dim")
    meta.append(f"Generated {data['generated_at']}  ·  Auth via {auth_source}")
    if data["filters"]:
        filters = ", ".join(f"{k}={v}" for k, v in data["filters"].items())
        meta.append(f"  ·  Filters {filters}")

    return Panel(
        Group(title, scope, meta),
        box=box.ROUNDED,
        border_style="bright_cyan",
        padding=(0, 2),
    )


def render_tiles(summary, width):
    """Stat tiles: affected packages plus one tile per severity."""

    fits_row = width >= 10 * (len(SEVERITIES) + 1)

    def tile(label, value, style, caption):
        body = Text(justify="center", no_wrap=True, overflow="ellipsis")
        body.append(f"{value:,}\n", style=f"bold {style}" if value else "grey50")
        body.append(f"{label}\n", style="bold" if value else "dim")
        body.append(caption, style="dim")
        return Panel(
            body,
            box=box.ROUNDED,
            border_style=style if value else "grey30",
            padding=(0, 0),
            width=None if fits_row else 14,
        )

    affected = summary["packages_affected_by"]
    tiles = [tile("Packages", summary["packages"], "bright_cyan", "affected")]
    for s in SEVERITIES:
        tiles.append(
            tile(
                SEVERITY_LABELS[s],
                summary["vulnerabilities"][s],
                SEVERITY_STYLES[s],
                f"{affected[s]:,} pkg" + ("s" if affected[s] != 1 else ""),
            )
        )

    # One evenly spaced row when it fits, otherwise let the tiles wrap
    if fits_row:
        grid = Table.grid(expand=True, padding=(0, 1))
        for _ in tiles:
            grid.add_column(ratio=1)
        grid.add_row(*tiles)
        return grid
    return Columns(tiles)


def render_distribution(totals, width):
    """Full-width severity distribution bar with a percentage legend."""
    grand = sum(totals[s] for s in SEVERITIES)
    items = [Text(f"{grand:,} findings", style="bold")]
    for s in SEVERITIES:
        if totals[s]:
            item = Text("■ ", style=SEVERITY_STYLES[s])
            item.append(f"{SEVERITY_LABELS[s]} ")
            share = totals[s] / grand
            item.append(f"{share:.0%}" if share >= 0.005 else "<1%", style="dim")
            items.append(item)
    # Columns wraps between legend items rather than inside them
    return Group(severity_bar(totals, width), Columns(items, padding=(0, 3)))


def _severity_columns(table, show_malware):
    for s in SEVERITIES:
        if s == "malware" and not show_malware:
            continue
        table.add_column(
            SEVERITY_SHORT[s],
            justify="right",
            header_style=SEVERITY_STYLES[s],
            no_wrap=True,
        )


def render_repositories(repos, show_malware, bar_width):
    """Per-repository breakdown table for workspace reports."""
    table = Table(
        title="Repositories",
        title_style="bold",
        title_justify="left",
        box=box.SIMPLE_HEAD,
        header_style="bold",
        expand=True,
    )
    table.add_column("Repository", style="cyan", ratio=1, min_width=12, overflow="fold")
    table.add_column("Pkgs", justify="right", no_wrap=True)
    _severity_columns(table, show_malware)
    table.add_column("Total", justify="right", style="bold", no_wrap=True)
    if bar_width:
        table.add_column("Distribution", width=bar_width, no_wrap=True)

    scale = max((r["num_vulnerabilities"] for r in repos), default=0)
    for repo in repos:
        v = repo["vulnerabilities"]
        row = [repo["repository"], f"{repo['packages']:,}"]
        row += [count_cell(v[s], s) for s in SEVERITIES if s != "malware" or show_malware]
        row.append(f"{repo['num_vulnerabilities']:,}")
        if bar_width:
            row.append(severity_bar(v, bar_width, scale))
        table.add_row(*row)
    return table


def render_packages(data, show_malware, bar_width, wide):
    """Ranked package table.

    On narrow terminals the format and download columns are dropped and
    the repository moves under the package name.
    """
    packages = data["packages"]
    workspace_scope = data["scope"] == "workspace"
    total = data["summary"]["packages"]

    truncated = len(packages) < total
    if workspace_scope and truncated:
        title = f"Top {len(packages):,} most impacted packages"
        caption = (
            f"{total:,} vulnerable packages in total · use --repo <repo> "
            "for a repository's full list, or --limit 0 for all"
        )
    else:
        title = "Packages"
        caption = (
            f"Showing top {len(packages):,} of {total:,} packages · "
            "use --limit 0 to show all"
            if truncated
            else None
        )

    table = Table(
        title=title,
        title_style="bold",
        title_justify="left",
        box=box.SIMPLE_HEAD,
        header_style="bold",
        expand=True,
        caption=caption,
        caption_style="dim",
        caption_justify="left",
    )
    table.add_column("#", justify="right", style="grey50", no_wrap=True)
    table.add_column("Package", ratio=1, min_width=16, overflow="fold")
    table.add_column("Version", style="dim", no_wrap=True)
    if wide:
        table.add_column("Format", style="grey62", no_wrap=True)
        if workspace_scope:
            table.add_column("Repository", style="cyan", overflow="fold")
        table.add_column("DLs", justify="right", style="grey62", no_wrap=True)
    _severity_columns(table, show_malware)
    table.add_column("Total", justify="right", style="bold", no_wrap=True)
    if bar_width:
        table.add_column("Severity", width=bar_width, no_wrap=True)

    scale = max((p["num_vulnerabilities"] for p in packages), default=0)
    for rank, pkg in enumerate(packages, start=1):
        v = pkg["vulnerabilities"]
        name = Text(pkg["package"], style="bold")
        if v["malware"]:
            name.append(" MALWARE", style="bold white on magenta")
        if workspace_scope and not wide:
            name.append(f"\n{pkg['repository']}", style="cyan")

        row = [str(rank), name, short_version(pkg["version"], 14 if wide else 10)]
        if wide:
            row.append(pkg["format"])
            if workspace_scope:
                row.append(pkg["repository"])
            row.append(f"{pkg['downloads'] or 0:,}")
        row += [count_cell(v[s], s) for s in SEVERITIES if s != "malware" or show_malware]
        row.append(f"{pkg['num_vulnerabilities']:,}")
        if bar_width:
            row.append(severity_bar(v, bar_width, scale))
        table.add_row(*row)
    return table


def render_report(console, report, auth_source, elapsed):
    """Print the full rich report."""
    data = report["data"]
    summary = data["summary"]
    totals = summary["vulnerabilities"]

    console.print()
    console.print(render_header(data, auth_source))

    if not summary["packages"]:
        console.print(
            Panel(
                Text("✓ No vulnerable packages found", style="bold green", justify="center"),
                border_style="green",
                box=box.ROUNDED,
            )
        )
        return

    # Only spend columns on malware / bars when they carry information
    show_malware = totals["malware"] > 0
    wide = console.width >= 130
    bar_width = 16 if console.width >= 150 else 0

    console.print(render_tiles(summary, console.width))
    console.print(render_distribution(totals, max(console.width - 2, 10)))
    console.print()

    if data["scope"] == "workspace" and summary["repositories"] > 1:
        console.print(render_repositories(data["repositories"], show_malware, bar_width))

    console.print(render_packages(data, show_malware, bar_width, wide))
    console.print(Rule(style="grey30"))
    console.print(
        f"[dim]{summary['packages']:,} vulnerable packages · "
        f"{totals['total']:,} OSV findings · fetched in {elapsed:.1f}s[/]"
    )


# --- Entry point ---


def main(argv=None):
    """Fetch OSV vulnerability summaries and render them."""
    args = get_args(argv)
    log = stderr_console  # status messages to stderr
    start_time = time.time()

    try:
        token, auth_source = resolve_credential(args)
        session = make_session(token)
        raw_packages = fetch_packages(session, args, log)
        report = build_report(args, raw_packages)
        elapsed = time.time() - start_time

        if args.output == "json":
            sys.stdout.write(json.dumps(report, indent=2) + "\n")
        else:
            render_report(stdout_console, report, auth_source, elapsed)
        return 0

    except AuthError as e:
        log.print(f"[bold red]Authentication error:[/] {e}")
    except ApiError as e:
        scope = f"{args.workspace}/{args.repo}" if args.repo else args.workspace
        messages = {
            401: "credentials were rejected. Check your API key or re-run `cloudsmith auth`.",
            403: f"you do not have permission to view vulnerabilities for '{scope}'.",
            404: f"'{scope}' was not found.",
        }
        log.print(
            f"[bold red]API error {e.status_code}:[/] "
            + messages.get(e.status_code, e.detail)
        )
    except requests.RequestException as e:
        log.print(f"[bold red]Network error:[/] {e}")
    except KeyboardInterrupt:
        log.print("[yellow]Interrupted.[/]")
        return 130
    return 1


if __name__ == "__main__":
    sys.exit(main())
