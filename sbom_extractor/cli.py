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
from sbom_extractor.scanner import DEFAULT_EXCLUDES, ProjectScanner, process_file_batch
from sbom_extractor.compilation_db import CompilationDatabaseParser
from sbom_extractor.manifest_parser import ManifestParser
from sbom_extractor.spdx_generator import SPDXGenerator, HTML_FILES_CAP
from sbom_extractor.spdx3_generator import SPDX3Generator
from sbom_extractor.cyclonedx_generator import CycloneDXGenerator
from sbom_extractor.html_generator import HTMLGenerator
from sbom_extractor.vcs import get_git_metadata
from sbom_extractor import ntia, validator

_err = Console(stderr=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sbom-extractor",
        description=f"sbom-extractor v{__version__} — Extract SPDX / CycloneDX SBOMs from open-source projects.",
    )
    parser.add_argument("path", help="Path to the project directory to scan")
    parser.add_argument("-o", "--output", default="sbom",
                        help="Base filename for output files (default: sbom)")
    parser.add_argument("--format",
                        choices=["spdx", "spdx3", "cyclonedx", "html", "all"],
                        default="all", help="Output format (default: all)")
    parser.add_argument("--project-name", help="Project name (default: directory name)")
    parser.add_argument("--project-version", default="1.0.0",
                        help="Project version (default: 1.0.0)")
    parser.add_argument("--supplier",
                        help="Supplier / organization name (embedded in SBOM metadata, required for NTIA compliance)")
    parser.add_argument("--no-hashes", action="store_true",
                        help="Skip SHA-256/SHA-1 hashing (much faster for large projects)")
    parser.add_argument("--reproducible", action="store_true",
                        help="Produce deterministic output: fixed timestamp and UUID derived from project name/version")
    parser.add_argument("--compile-commands",
                        help="Path to compile_commands.json (Clang compilation database)")
    parser.add_argument("--kernel-build",
                        help="Path to kernel build directory (scans Kbuild .cmd files)")
    parser.add_argument("--exclude", action="append", default=[], metavar="DIR",
                        help="Additional directory name to exclude (repeatable)")
    parser.add_argument("--workers", type=int, default=None,
                        help="Parallel worker threads (default: 2 × CPU count, max 32)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress all progress output")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show extra detail (license breakdown, validation results)")
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


def _build_generator_kwargs(args, git_info) -> dict:
    return dict(
        git_info=git_info,
        supplier=args.supplier,
        reproducible=args.reproducible,
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
                f"Target  : [dim]{project_path}[/dim]"
                + (f"\nSupplier: [dim]{args.supplier}[/dim]" if args.supplier else "")
                + ("\n[dim italic]Reproducible mode[/dim italic]" if args.reproducible else ""),
                title="SBOM Extraction",
                border_style="blue",
            )
        )

    t_start = time.monotonic()
    exclude_dirs: Set[str] = DEFAULT_EXCLUDES | set(args.exclude)
    files: List[Dict[str, Any]] = []

    # ── Git metadata ──────────────────────────────────────────────────
    git_info = get_git_metadata(project_path)
    if git_info and not quiet:
        commit_str = git_info.get("commit_short", "")
        label = git_info.get("tag") or git_info.get("branch") or commit_str
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

            # Deduplicate: the same header can appear in many translation units
            seen_paths: set = set()
            deduped = []
            for e in compiled:
                if e["absolute_path"] not in seen_paths:
                    seen_paths.add(e["absolute_path"])
                    deduped.append(e)
            if len(deduped) < len(compiled) and not quiet:
                _err.print(
                    f"[dim]Deduplicated {len(compiled) - len(deduped):,} duplicate "
                    f"entries from compile_commands.json[/dim]"
                )

            task = progress.add_task("[cyan]Processing compiled files…", total=len(deduped))
            entries = [(e["absolute_path"], e["path"], e["name"]) for e in deduped]

            def _on_db(done: int, total: int) -> None:
                progress.update(task, completed=done, total=total)

            files = process_file_batch(
                entries, calculate_hashes_flag=not args.no_hashes,
                on_progress=_on_db, max_workers=args.workers,
            )
            progress.update(task, completed=len(deduped))

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

            def _on_kb(done: int, total: int) -> None:
                progress.update(proc_task, completed=done, total=total)

            files = process_file_batch(
                entries, calculate_hashes_flag=not args.no_hashes,
                on_progress=_on_kb, max_workers=args.workers,
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

    # ── NTIA compliance check ─────────────────────────────────────────
    ntia_issues = ntia.check(
        project_name=project_name,
        project_version=args.project_version,
        dependencies=dependencies,
        supplier=args.supplier,
        has_timestamp=not args.reproducible,
    )
    if not quiet:
        if ntia_issues:
            _err.print(
                f"[yellow]⚠ NTIA minimum elements: {len(ntia_issues)} issue(s)[/yellow]"
            )
            for issue in ntia_issues:
                _err.print(f"  [yellow]•[/yellow] {issue}")
        else:
            _err.print("[green]✓[/green] NTIA minimum elements: all present")

    # ── Generator kwargs ──────────────────────────────────────────────
    gen_kwargs = _build_generator_kwargs(args, git_info)

    formats: List[str] = (
        ["spdx", "spdx3", "cyclonedx", "html"] if args.format == "all" else [args.format]
    )
    need_spdx = "spdx" in formats or "html" in formats
    need_spdx3 = "spdx3" in formats or "html" in formats
    need_cdx = "cyclonedx" in formats or "html" in formats
    need_html = "html" in formats

    if not quiet:
        _err.print("[+] Generating SBOM documents…")

    output_dir = os.path.dirname(os.path.abspath(args.output))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    written: List[str] = []
    validation_errors: Dict[str, List[str]] = {}

    # ── SPDX 2.3 ─────────────────────────────────────────────────────
    spdx_doc: Optional[Dict] = None
    if need_spdx:
        spdx_gen = SPDXGenerator(project_name, args.project_version, **gen_kwargs)
        if "spdx" in formats:
            path = f"{args.output}.spdx.json"
            try:
                spdx_gen.write_streaming(files, dependencies, path)
                written.append(path)
                # Validate a small in-memory version (avoid re-parsing huge file)
                mini = spdx_gen.generate(files[:100], dependencies, max_files=100)
                errs = validator.validate_spdx(mini)
                if errs:
                    validation_errors["spdx"] = errs
            except Exception as e:
                _err.print(f"[red]Error writing SPDX file:[/red] {e}")
        if need_html:
            spdx_doc = spdx_gen.generate(files, dependencies)

    # ── SPDX 3.0.1 ───────────────────────────────────────────────────
    spdx3_doc: Optional[Dict] = None
    if need_spdx3:
        spdx3_gen = SPDX3Generator(project_name, args.project_version, **gen_kwargs)
        if "spdx3" in formats:
            path = f"{args.output}.spdx3.json"
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(
                        spdx3_gen.generate(files, dependencies), f, indent=2
                    )
                written.append(path)
            except Exception as e:
                _err.print(f"[red]Error writing SPDX 3 file:[/red] {e}")
        if need_html:
            spdx3_doc = spdx3_gen.generate(files, dependencies)

    # ── CycloneDX 1.5 ────────────────────────────────────────────────
    cdx_doc: Optional[Dict] = None
    if need_cdx:
        cdx_gen = CycloneDXGenerator(project_name, args.project_version, **gen_kwargs)
        if "cyclonedx" in formats:
            path = f"{args.output}.cdx.json"
            try:
                cdx_gen.write_streaming(files, dependencies, path)
                written.append(path)
                mini_cdx = cdx_gen.generate(files[:100], dependencies, max_files=100)
                errs = validator.validate_cyclonedx(mini_cdx)
                if errs:
                    validation_errors["cyclonedx"] = errs
            except Exception as e:
                _err.print(f"[red]Error writing CycloneDX file:[/red] {e}")
        if need_html:
            cdx_doc = cdx_gen.generate(files, dependencies)

    # ── HTML dashboard ────────────────────────────────────────────────
    if need_html:
        path = f"{args.output}.html"
        try:
            html_files = files
            truncated_msg = ""
            if len(files) > HTML_FILES_CAP:
                html_files = files[:HTML_FILES_CAP]
                truncated_msg = (
                    f"  [yellow]HTML dashboard shows first {HTML_FILES_CAP:,} "
                    f"of {len(files):,} files[/yellow]"
                )
            html_gen = HTMLGenerator(project_name, args.project_version)
            html_content = html_gen.generate(html_files, dependencies, spdx_doc, cdx_doc, spdx3_doc)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_content)
            written.append(path)
            if truncated_msg and not quiet:
                _err.print(truncated_msg)
        except Exception as e:
            _err.print(f"[red]Error writing HTML file:[/red] {e}")

    # ── Validation results ────────────────────────────────────────────
    if validation_errors and (verbose or not quiet):
        for fmt, errs in validation_errors.items():
            _err.print(f"[red]Validation errors ({fmt}):[/red]")
            for err in errs:
                _err.print(f"  [red]•[/red] {err}")

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
        table.add_row("Distinct licenses", str(len(distinct_licenses)))
        if distinct_licenses:
            sample = ", ".join(sorted(distinct_licenses)[:6])
            if len(distinct_licenses) > 6:
                sample += f" … (+{len(distinct_licenses) - 6})"
            table.add_row("License sample", sample)
        if args.supplier:
            table.add_row("Supplier", args.supplier)
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
