# Copyright 2026 Cloudsmith Ltd

import argparse
import json
import os
import sys
import time
from collections import Counter

import requests
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

# --- Configuration ---
API_KEY = os.environ.get("CLOUDSMITH_API_KEY")
PAGE_SIZE = 100  # max items per page
BASE_API = "https://api.cloudsmith.io"

# stderr console for progress/status, stdout stays clean for json output
stderr_console = Console(stderr=True)
stdout_console = Console()


def get_args():
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Cloudsmith Repository Vulnerability Overview"
    )
    parser.add_argument(
        "--owner",
        required=True,
        help="Organization/owner slug on Cloudsmith.",
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Repository slug on Cloudsmith.",
    )
    parser.add_argument(
        "--vulnerable-only",
        action="store_true",
        help="Only include packages that have at least one vulnerability.",
    )
    parser.add_argument(
        "--output",
        choices=["table", "json"],
        default="table",
        help="Output format: 'table' (default) or 'json'.",
    )
    return parser.parse_args()


def _no_cache_headers(headers):
    """Return headers with cache-busting directives."""
    return {
        **headers,
        "Cache-Control": "no-cache, no-store",
        "Pragma": "no-cache",
    }


def api_get(url, headers, params=None):
    """Make a GET request with cache-busting headers."""
    return requests.get(url, headers=_no_cache_headers(headers), params=params)


def fetch_paginated(url, headers, progress, task, params=None):
    """Fetch all pages from a paginated endpoint, returning a flat list."""
    all_results = []
    page = 1

    while True:
        page_params = {"page": page, "page_size": PAGE_SIZE}
        if params:
            page_params.update(params)

        progress.update(
            task,
            description=(
                f"[cyan]Fetching page {page}... "
                f"({len(all_results)} packages so far)"
            ),
        )

        response = api_get(url, headers, params=page_params)

        if response.status_code != 200:
            stderr_console.print(
                f"[bold red]Error:[/] {response.status_code} - {response.text}"
            )
            return None

        results = response.json()
        if not isinstance(results, list):
            results = [results]

        all_results.extend(results)
        progress.update(
            task,
            description=(
                f"[cyan]Fetched {len(all_results)} packages ({page} pages)"
            ),
        )

        if len(results) < PAGE_SIZE:
            break

        page += 1

    return all_results


def fetch_scan_data(owner, repo, package_slug, scan_identifier, headers):
    """Fetch full scan data including nested scans[].results[].

    Endpoint: GET /v1/vulnerabilities/{owner}/{repo}/{package_slug}/{scan_identifier}/
    """
    url = (
        f"{BASE_API}/v1/vulnerabilities/{owner}/{repo}/"
        f"{package_slug}/{scan_identifier}/"
    )
    response = api_get(url, headers)

    if response.status_code != 200:
        return None

    data = response.json()

    if isinstance(data, dict) and data.get("scans"):
        return data

    return None


def count_severities(scan_data):
    """Count vulnerability severities from scans[].results[].severity.

    Iterates over each scan target in the scans[] array and tallies
    the severity field from each result (vulnerability) entry.
    """
    severity_keys = ("critical", "high", "medium", "low", "unknown")
    counts = {k: 0 for k in severity_keys}

    if not scan_data or not isinstance(scan_data, dict):
        return counts

    scans = scan_data.get("scans", [])
    if not isinstance(scans, list):
        return counts

    severities = []
    for scan in scans:
        results = scan.get("results", [])
        if not isinstance(results, list):
            continue
        for vuln in results:
            severity = vuln.get("severity", "Unknown").strip().lower()
            severities.append(severity)

    tally = Counter(severities)
    for key in severity_keys:
        counts[key] = tally.get(key, 0)

    return counts


def fetch_and_display():
    """Fetch vulnerability scans and display results."""
    if not API_KEY:
        stderr_console.print(
            "[bold red]Error:[/] CLOUDSMITH_API_KEY environment variable is not set."
        )
        return

    args = get_args()
    owner = args.owner
    repo = args.repo
    is_json = args.output == "json"
    log = stderr_console  # status messages to stderr
    scans_url = f"{BASE_API}/vulnerabilities/{owner}/{repo}/"
    headers = {"Accept": "application/json", "X-Api-Key": API_KEY}
    start_time = time.time()

    try:
        # Step 1: fetch all scans (paginated)
        log.print(
            f"\n[bold blue]⬡ Cloudsmith Repository Vulnerability Overview[/bold blue]"
            f"\n  Owner: [cyan]{owner}[/]  Repo: [cyan]{repo}[/]\n"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            transient=True,
            console=log,
        ) as progress:
            task = progress.add_task(
                "[cyan]Connecting to Cloudsmith API...", total=None
            )
            scans = fetch_paginated(scans_url, headers, progress, task)

        if scans is None:
            return

        log.print(f"  [green]✓[/] Found [bold]{len(scans)}[/] packages\n")

        # Step 2: count how many need detail fetches
        vulnerable_scans = [
            s for s in scans if s.get("has_vulnerabilities")
        ]
        skipped = (
            len(scans) - len(vulnerable_scans) if args.vulnerable_only else 0
        )

        if vulnerable_scans:
            log.print(
                f"  [yellow]![/] [bold]{len(vulnerable_scans)}[/] "
                f"packages have vulnerabilities"
            )
        else:
            log.print(
                "  [green]✓[/] No vulnerabilities found across all packages"
            )

        if args.vulnerable_only and skipped:
            log.print(
                f"  [dim]Skipping {skipped} clean packages "
                f"(--vulnerable-only)[/]"
            )

        log.print()

        # Step 3: initialize report
        report = {
            "data": {"owner": owner, "packages": [], "repository": repo}
        }

        # Step 4: fetch scan details for vulnerable packages
        detail_count = len(vulnerable_scans)
        processed = 0
        errors = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=log,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "[cyan]Fetching vulnerability details...",
                total=(
                    detail_count if args.vulnerable_only else len(scans)
                ),
            )

            for scan in scans:
                is_vulnerable = scan.get("has_vulnerabilities", False)
                num_vulns = scan.get("num_vulnerabilities", 0)

                if args.vulnerable_only and not is_vulnerable:
                    continue

                pkg_info = scan.get("package", {})
                scan_id = scan.get("identifier")
                pkg_slug = pkg_info.get("identifier")
                pkg_name = pkg_info.get("name", "unknown")

                progress.update(
                    task,
                    description=(
                        f"[cyan]Scanning [bold]{pkg_name}[/bold]..."
                    ),
                )

                # Only fetch detail for vulnerable packages
                v_counts = {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unknown": 0,
                }
                if is_vulnerable and scan_id and pkg_slug:
                    scan_data = fetch_scan_data(
                        owner, repo, pkg_slug, scan_id, headers
                    )
                    if scan_data:
                        v_counts = count_severities(scan_data)
                        processed += 1
                    else:
                        errors += 1

                status = "vulnerable" if is_vulnerable else "no_issues_found"
                pkg_version = pkg_info.get("version", "")

                report["data"]["packages"].append({
                    "package": pkg_name,
                    "version": pkg_version,
                    "slug_perm": pkg_slug,
                    "status": status,
                    "num_vulnerabilities": num_vulns,
                    "vulnerabilities": v_counts,
                })

                progress.advance(task)

        # Step 5: summary stats
        elapsed = time.time() - start_time
        log.print(
            f"  [green]✓[/] Processed [bold]{processed}[/] vulnerability scans"
            + (f" ([red]{errors} errors[/])" if errors else "")
            + f" in [bold]{elapsed:.1f}s[/]\n"
        )

        # Step 6: sort by total vulnerabilities descending
        report["data"]["packages"].sort(
            key=lambda p: p["num_vulnerabilities"], reverse=True
        )

        # Step 7: output
        if not report["data"]["packages"]:
            log.print(
                "[yellow]No packages found matching the criteria.[/]"
            )
        elif is_json:
            sys.stdout.write(json.dumps(report, indent=2) + "\n")
        else:
            table = Table(
                title=f"Vulnerability Report: {repo}",
                header_style="bold magenta",
                show_lines=False,
                padding=(0, 1),
            )
            table.add_column("Package", style="cyan", no_wrap=True)
            table.add_column("Version", style="dim")
            table.add_column("Status", justify="center")
            table.add_column("Total", justify="right")
            table.add_column("Crit", style="red", justify="right")
            table.add_column("High", style="orange3", justify="right")
            table.add_column("Med", style="yellow", justify="right")
            table.add_column("Low", style="green", justify="right")

            for pkg in report["data"]["packages"]:
                is_vulnerable = pkg["status"] == "vulnerable"
                v_counts = pkg["vulnerabilities"]
                status_display = (
                    "[bold red]VULNERABLE[/]"
                    if is_vulnerable
                    else "[dim green]No issues found[/]"
                )
                table.add_row(
                    pkg["package"],
                    pkg["version"],
                    status_display,
                    str(pkg["num_vulnerabilities"]),
                    str(v_counts["critical"]),
                    str(v_counts["high"]),
                    str(v_counts["medium"]),
                    str(v_counts["low"]),
                )

            stdout_console.print(table)

            # Footer summary
            total_pkgs = len(report["data"]["packages"])
            total_vuln = sum(
                1
                for p in report["data"]["packages"]
                if p["status"] == "vulnerable"
            )
            total_crit = sum(
                p["vulnerabilities"]["critical"]
                for p in report["data"]["packages"]
            )
            total_high = sum(
                p["vulnerabilities"]["high"]
                for p in report["data"]["packages"]
            )
            stdout_console.print(
                f"\n  [bold]{total_pkgs}[/] packages scanned, "
                f"[bold red]{total_vuln}[/] vulnerable"
                + (
                    f" ([red]{total_crit} critical[/], "
                    f"[orange3]{total_high} high[/])"
                    if total_crit or total_high
                    else ""
                )
            )

    except Exception as e:
        stderr_console.print(
            f"[bold red]An unexpected error occurred:[/] {e}"
        )


if __name__ == "__main__":
    fetch_and_display()