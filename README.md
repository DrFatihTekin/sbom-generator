# OpenSBOM Extractor

[![CI](https://github.com/DrFatihTekin/sbom-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/DrFatihTekin/sbom-generator/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/sbom-generator)](https://pypi.org/project/sbom-generator/)
[![Python](https://img.shields.io/pypi/pyversions/sbom-generator)](https://pypi.org/project/sbom-generator/)
[![Downloads](https://img.shields.io/pypi/dm/sbom-generator)](https://pypi.org/project/sbom-generator/)

A production-ready Python CLI for extracting Software Bill of Materials (SBOM) from open-source codebases. Built for scale — from small libraries to the Linux kernel (70k+ files).

---

## Key Features

- **Multi-ecosystem dependency extraction** — parses manifests and lock files for Python, Node.js, Rust, Go, and Java (Maven + Gradle). Lock files are preferred over manifests for exact pinned versions.
- **Parallel file scanning** — thread pool for hashing and license extraction with a live progress bar.
- **Streaming JSON output** — SPDX and CycloneDX documents are written one entry at a time; the full document is never held in memory, making 70k+ file projects practical.
- **Correct PURL generation** — all package references follow the [Package URL spec](https://github.com/package-url/purl-spec) (`pkg:pypi/…`, `pkg:maven/…`, etc.).
- **CPE identifiers** — best-effort CPE 2.3 strings generated for every dependency, enabling vulnerability matching against the NVD.
- **SPDX expression support** — correctly preserves compound identifiers like `GPL-2.0-only OR MIT` and `GPL-2.0-only WITH Linux-syscall-note`.
- **Git VCS metadata** — embeds commit, branch, tag, and remote URL into every SBOM format.
- **Reproducible output** — `--reproducible` produces bit-identical SBOMs across runs (fixed timestamp, deterministic UUID).
- **NTIA minimum elements check** — validates the 7 NTIA-required fields at runtime and reports any gaps.
- **SBOM structural validation** — validates generated SPDX 2.3 and CycloneDX 1.5 documents before writing.
- **Standards-compliant output** — SPDX 2.3, SPDX 3.0.1, and CycloneDX 1.5 JSON; plus an interactive HTML dashboard.
- **Precision C/C++ build tracing** — via Clang `compile_commands.json` or Linux kernel Kbuild `.cmd` files.

---

## Supported Languages

### License detection

SPDX license tags are extracted from any source file, including: C, C++, Python, JavaScript, TypeScript, Go, Rust, Java, Kotlin, Swift, C#, Shell, Perl, Ruby, PHP, Lua, Assembly, and common config formats (YAML, TOML, JSON, Makefile, Kconfig).

### Dependency extraction

| Ecosystem | Files parsed (lock file preferred) |
|---|---|
| Python | `poetry.lock` / `requirements.txt` / `requirements.in`, `pyproject.toml` |
| Node.js | `package-lock.json` / `package.json` |
| Rust | `Cargo.lock` / `Cargo.toml` |
| Go | `go.sum` / `go.mod` |
| Java (Maven) | `pom.xml` — including sub-modules and `<properties>` resolution |
| Java (Gradle) | `gradle.lockfile` / `build.gradle` / `build.gradle.kts` |

---

## Installation

```bash
pip install sbom-generator
```

For development:

```bash
pip install -e .
```

Requires Python 3.9+. The only runtime dependency is [`rich`](https://github.com/Textualize/rich) for progress display.

---

## Usage

### General directory scan

```bash
sbom-extractor /path/to/project -o my-project-sbom
```

### With supplier name (required for NTIA compliance)

```bash
sbom-extractor /path/to/project --supplier "Acme Corp" -o my-project-sbom
```

### Reproducible output (for SBOM diffing in CI)

```bash
sbom-extractor /path/to/project --reproducible -o my-project-sbom
```

### C/C++ project with a Clang compilation database

```bash
sbom-extractor /path/to/project \
  --compile-commands /path/to/project/compile_commands.json \
  -o project-sbom
```

Generate `compile_commands.json` with CMake (`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`) or [Bear](https://github.com/rizsotto/Bear).

### Linux kernel (compile_commands.json)

```bash
cd /path/to/linux
make defconfig && make -j$(nproc)
python3 scripts/clang-tools/gen_compile_commands.py

sbom-extractor /path/to/linux \
  --compile-commands /path/to/linux/compile_commands.json \
  --no-hashes \
  -o linux-sbom
```

### Linux kernel (Kbuild .cmd files)

```bash
sbom-extractor /path/to/linux \
  --kernel-build /path/to/linux/build-output \
  --no-hashes \
  -o linux-sbom
```

`--no-hashes` is recommended for kernel-scale projects to skip SHA-256/SHA-1 computation.

---

## CLI Options

```
positional arguments:
  path                        Path to the project directory to scan

options:
  -h, --help                  Show this help message and exit
  -o, --output OUTPUT         Base filename for output files (default: sbom)
  --format {spdx,spdx3,cyclonedx,html,all}
                              Output format (default: all)
  --project-name NAME         Project name (default: directory name)
  --project-version VERSION   Project version (default: 1.0.0)
  --supplier NAME             Supplier / organization name — required for NTIA compliance
  --no-hashes                 Skip SHA-256/SHA-1 hashing (faster for large projects)
  --reproducible              Deterministic output: fixed timestamp, UUID derived from
                              project name/version — useful for SBOM diffing in CI
  --compile-commands PATH     Path to compile_commands.json
  --kernel-build PATH         Path to kernel build directory (Kbuild .cmd files)
  --exclude DIR               Exclude a directory name from scanning (repeatable)
  --workers N                 Number of parallel worker threads (default: 2 × CPU count)
  -q, --quiet                 Suppress all progress output
  -v, --verbose               Show extra detail (full license list, validation results)
```

---

## Output Files

| File | Format | Notes |
|---|---|---|
| `sbom.spdx.json` | SPDX 2.3 | Stream-written; validated before save |
| `sbom.spdx3.json` | SPDX 3.0.1 | JSON-LD graph format |
| `sbom.cdx.json` | CycloneDX 1.5 | Stream-written; validated before save; includes CPE |
| `sbom.html` | Interactive HTML | Dark-mode dashboard; file list capped at 5,000 for browser performance |

Use `--format spdx`, `--format cyclonedx`, etc. to generate only what you need.

---

## NTIA Compliance

The tool checks the [NTIA minimum elements](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials) at runtime:

| Element | How it's satisfied |
|---|---|
| Supplier name | `--supplier` flag |
| Component name | `--project-name` (or directory name) |
| Component version | `--project-version` |
| Unique identifiers | PURL + CPE generated for every dependency |
| Dependency relationships | `CONTAINS` / `DEPENDS_ON` relationships in all formats |
| Author of SBOM data | Tool name + version in `creationInfo` |
| Timestamp | UTC timestamp at generation time (or epoch with `--reproducible`) |

Any missing elements are reported as warnings at the end of every run.

---

## Architecture

| Module | Responsibility |
|---|---|
| `cli.py` | Entry point — argument parsing, progress display, orchestration |
| `scanner.py` | Parallel directory walk, license extraction, file hashing |
| `manifest_parser.py` | Manifest and lock file parsing for all supported ecosystems |
| `compilation_db.py` | Clang `compile_commands.json` and Kbuild `.cmd` parsing |
| `purl.py` | Canonical PURL generation |
| `cpe.py` | Best-effort CPE 2.3 generation |
| `vcs.py` | Git metadata extraction |
| `ntia.py` | NTIA minimum elements compliance check |
| `validator.py` | Structural validation for SPDX 2.3 and CycloneDX 1.5 |
| `spdx_generator.py` | SPDX 2.3 JSON output (in-memory + streaming) |
| `spdx3_generator.py` | SPDX 3.0.1 JSON-LD output |
| `cyclonedx_generator.py` | CycloneDX 1.5 JSON output (in-memory + streaming) |
| `html_generator.py` | Self-contained interactive HTML report |
