import json
import os
import sys
import time
import argparse
from typing import Any, Dict, List, Optional, Set

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich import box

from sbom_extractor import __version__
from sbom_extractor.scanner import (
    DEFAULT_EXCLUDES,
    ProjectScanner,
    extract_spdx_license,
    calculate_hashes,
    is_text_file,
    process_file_batch,
)
from sbom_extractor.compilation_db import CompilationDatabaseParser
from sbom_extractor.manifest_parser import ManifestParser
from sbom_extractor.spdx_generator import SPDXGenerator
from sbom_extractor.spdx3_generator import SPDX3Generator
from sbom_extractor.cyclonedx_generator import CycloneDXGenerator
from sbom_extractor.html_generator import HTMLGenerator
from sbom_extractor.vcs import get_git_metadata

# All progress and diagnostic output goes to stderr so stdout stays clean.
_err = Console(stderr=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sbom-extractor",
        description=f"sbom-extractor v{__version__} — Extract SPDX / CycloneDX SBOMs from open-source projects.",
    )
    parser.add_argument("path", help="Path to the project directory to scan")
    parser.add_argument(
        "-o", "--output", default="sbom",
        help="Base filename for output files (default: sbom)",
    )
    parser.add_argument(
        "--format", choices=["spdx", "spdx3", "cyclonedx", "html", "all"],
        default="all",
        help="Output format (default: all)",
    )
    parser.add_argument("--project-name", help="Project name (default: directory name)")
    parser.add_argument(
        "--project-version", default="1.0.0",
        help="Project version (default: 1.0.0)",
    )
    parser.add_argument(
        "--no-hashes", action="store_true",
        help="Skip SHA-256/SHA-1 file hashing (much faster for large projects)",
    )
    parser.add_argument(
        "--compile-commands",
        help="Path to compile_commands.json (Clang compilation database)",
    )
    parser.add_argument(
        "--kernel-build",
        help="Path to kernel build directory (scans Kbuild .cmd files)",
    )
    parser.add_argument(
        "--exclude", action="append", default=[], metavar="DIR",
        help="Additional directory name to exclude (can be repeated)",
    )
    parser.add_argument(
        "--workers", type=int, default=None,
        help="Number of parallel worker threads (default: 2 × CPU count, max 32)",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress all progress output",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show extra detail (per-format timing, license breakdown)",
    )
    return parser.parse_args()


def _make_progress(quiet: bool) -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=_err,
        disable=quiet,
        transient=False,
    )


def main() -> None:  # noqa: C901
    args = parse_args()

    project_path = os.path.abspath(args.path)
    if not os.path.exists(project_path):
        _err.print(f"[bold red]Error:[/] Path '{project_path}' does not exist.")
        sys.exit(1)

    project_name = args.project_name or os.path.basename(project_path) or "unknown-project"
    quiet = args.quiet
    verbose = args.verbose

    if not quiet:
        _err.print(
            Panel(
                f"[bold]sbom-extractor[/bold] [dim]v{__version__}[/dim]\n"
                f"Project : [cyan]{project_name}[/cyan]  v{args.project_version}\n"
                f"Target  : [dim]{project_path}[/dim]",
                title="SBOM Extraction",
                border_style="blue",
            )
        )

    t_start = time.monotonic()
    exclude_dirs: Set[str] = DEFAULT_EXCLUDES | set(args.exclude)
    files: List[Dict[str, Any]] = []

    # ── Git metadata ─────────────────────────────────────────────────
    git_info = get_git_metadata(project_path)
    if git_info and not quiet:
        commit_str = git_info.get("commit_short", "")
        branch_str = git_info.get("branch", "")
        tag_str = git_info.get("tag", "")
        label = tag_str or branch_str or commit_str
        _err.print(f"[dim]VCS: git  {label}  ({commit_str})[/dim]")

    # ── File scanning ─────────────────────────────────────────────────
    with _make_progress(quiet) as progress:

        # -- Mode 1: compile_commands.json --
        comp_db_path = args.compile_commands
        if not comp_db_path:
            candidate = os.path.join(project_path, "compile_commands.json")
            if os.path.exists(candidate):
                comp_db_path = candidate

        if comp_db_path:
            if not quiet:
                _err.print(f"[+] Using Clang compilation database: [cyan]{comp_db_path}[/cyan]")
            db_parser = CompilationDatabaseParser(project_path)
            compiled = db_parser.find_and_parse_compilation_db(comp_db_path)

            task = progress.add_task("[cyan]Processing compiled files…", total=len(compiled))
            entries = [
                (e["absolute_path"], e["path"], e["name"])
                for e in compiled
            ]

            def _on_prog_db(done: int, total: int) -> None:
                progress.update(task, completed=done, total=total)

            files = process_file_batch(
                entries,
                calculate_hashes_flag=not args.no_hashes,
                on_progress=_on_prog_db,
                max_workers=args.workers,
            )
            progress.update(task, completed=len(compiled))

        # -- Mode 2: kernel Kbuild .cmd files --
        elif args.kernel_build:
            kb_path = os.path.abspath(args.kernel_build)
            if not quiet:
                _err.print(f"[+] Scanning Kbuild directory: [cyan]{kb_path}[/cyan]")
            db_parser = CompilationDatabaseParser(project_path)

            discover_task = progress.add_task("[yellow]Discovering .cmd files…", total=None)
            kernel_paths = db_parser.parse_kernel_cmd_files(kb_path)
            progress.update(discover_task, total=1, completed=1)

            entries = [
                (p, os.path.relpath(p, project_path), os.path.basename(p))
                for p in kernel_paths
            ]
            proc_task = progress.add_task("[cyan]Processing kernel sources…", total=len(entries))

            def _on_prog_kb(done: int, total: int) -> None:
                progress.update(proc_task, completed=done, total=total)

            files = process_file_batch(
                entries,
                calculate_hashes_flag=not args.no_hashes,
                on_progress=_on_prog_kb,
                max_workers=args.workers,
            )
            progress.update(proc_task, completed=len(entries))

        # -- Mode 3: full directory walk --
        else:
            scan_task = progress.add_task("[cyan]Scanning directory…", total=None)

            def _on_scan(done: int, total: int) -> None:
                progress.update(scan_task, completed=done, total=total)

            scanner = ProjectScanner(
                project_path,
                exclude_dirs=exclude_dirs,
                calculate_file_hashes=not args.no_hashes,
                max_workers=args.workers,
            )
            files = scanner.scan(on_progress=_on_scan)

        # ── Manifest / lock file scanning ──────────────────────────────
        manifest_task = progress.add_task("[yellow]Parsing manifests…", total=None)
        manifest_parser = ManifestParser(project_path)
        dependencies = manifest_parser.scan_manifests()
        progress.update(manifest_task, total=1, completed=1)

    t_scan = time.monotonic()
    if not quiet:
        _err.print(
            f"[green]✓[/green] Scanned [bold]{len(files):,}[/bold] files  "
            f"and found [bold]{len(dependencies):,}[/bold] dependencies  "
            f"[dim]({t_scan - t_start:.1f}s)[/dim]"
        )

    # ── SBOM generation ───────────────────────────────────────────────
    formats: List[str] = (
        ["spdx", "spdx3", "cyclonedx", "html"] if args.format == "all" else [args.format]
    )
    need_spdx = "spdx" in formats or "html" in formats
    need_spdx3 = "spdx3" in formats or "html" in formats
    need_cdx = "cyclonedx" in formats or "html" in formats

    if not quiet:
        _err.print("[+] Generating SBOM documents…")

    spdx_doc: Optional[Dict] = None
    spdx3_doc: Optional[Dict] = None
    cdx_doc: Optional[Dict] = None

    if need_spdx:
        spdx_doc = SPDXGenerator(project_name, args.project_version, git_info=git_info).generate(
            files, dependencies
        )
    if need_spdx3:
        spdx3_doc = SPDX3Generator(project_name, args.project_version, git_info=git_info).generate(
            files, dependencies
        )
    if need_cdx:
        cdx_doc = CycloneDXGenerator(project_name, args.project_version, git_info=git_info).generate(
            files, dependencies
        )

    # ── Write outputs ─────────────────────────────────────────────────
    output_dir = os.path.dirname(os.path.abspath(args.output))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    written: List[str] = []

    if "spdx" in formats and spdx_doc is not None:
        path = f"{args.output}.spdx.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(spdx_doc, f, indent=2)
            written.append(path)
        except Exception as e:
            _err.print(f"[red]Error writing SPDX file:[/red] {e}")

    if "spdx3" in formats and spdx3_doc is not None:
        path = f"{args.output}.spdx3.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(spdx3_doc, f, indent=2)
            written.append(path)
        except Exception as e:
            _err.print(f"[red]Error writing SPDX 3 file:[/red] {e}")

    if "cyclonedx" in formats and cdx_doc is not None:
        path = f"{args.output}.cdx.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cdx_doc, f, indent=2)
            written.append(path)
        except Exception as e:
            _err.print(f"[red]Error writing CycloneDX file:[/red] {e}")

    if "html" in formats:
        path = f"{args.output}.html"
        try:
            html_gen = HTMLGenerator(project_name, args.project_version)
            html_content = html_gen.generate(files, dependencies, spdx_doc, cdx_doc, spdx3_doc)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_content)
            written.append(path)
        except Exception as e:
            _err.print(f"[red]Error writing HTML file:[/red] {e}")

    # ── Summary ───────────────────────────────────────────────────────
    t_total = time.monotonic() - t_start

    distinct_licenses = {
        item.get("license")
        for item in (files + dependencies)
        if item.get("license") and item["license"] != "NOASSERTION"
    }

    if not quiet:
        table = Table(box=box.ROUNDED, show_header=False, border_style="dim")
        table.add_column(style="dim", no_wrap=True)
        table.add_column(style="bold")
        table.add_row("Scanned files", f"{len(files):,}")
        table.add_row("Dependencies", f"{len(dependencies):,}")
        table.add_row("Distinct licenses", f"{len(distinct_licenses)}")
        if distinct_licenses:
            lic_sample = ", ".join(sorted(distinct_licenses)[:6])
            if len(distinct_licenses) > 6:
                lic_sample += f" … (+{len(distinct_licenses) - 6})"
            table.add_row("License sample", lic_sample)
        table.add_row("Total time", f"{t_total:.1f}s")
        _err.print(table)

        if verbose and distinct_licenses:
            _err.print("\n[bold]All detected licenses:[/bold]")
            for lic in sorted(distinct_licenses):
                _err.print(f"  {lic}")

        _err.print("\n[bold green]Output files:[/bold green]")
        for w in written:
            _err.print(f"  [cyan]{w}[/cyan]")

        _err.print("\n[bold green]✓ Done.[/bold green]")


if __name__ == "__main__":
    main()
