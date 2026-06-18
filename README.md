# OpenSBOM Extractor

[![CI](https://github.com/DrFatihTekin/sbom-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/DrFatihTekin/sbom-generator/actions/workflows/ci.yml)

A production-ready Python CLI for extracting Software Bill of Materials (SBOM) from open-source codebases. Built for scale — from small libraries to the Linux kernel (70k+ files).

---

## Key Features

- **Multi-ecosystem dependency extraction** — parses manifests and lock files for Python, Node.js, Rust, Go, and Java (Maven + Gradle). Lock files are preferred over manifests for exact pinned versions.
- **Parallel file scanning** — uses a thread pool for hashing and license extraction, with a live progress bar.
- **Correct PURL generation** — all package references follow the [Package URL spec](https://github.com/package-url/purl-spec) (`pkg:pypi/...`, `pkg:maven/...`, etc.).
- **SPDX expression support** — correctly preserves compound license identifiers like `GPL-2.0-only OR MIT` and `GPL-2.0-only WITH Linux-syscall-note`.
- **Git VCS metadata** — embeds commit, branch, tag, and remote URL into every SBOM format.
- **Standards-compliant output** — SPDX 2.3, SPDX 3.0.1, and CycloneDX 1.5 JSON; plus an interactive HTML dashboard.
- **Precision C/C++ build tracing** — via Clang `compile_commands.json` or Linux kernel Kbuild `.cmd` files.

---

## Supported Languages

### License detection

SPDX license tags are extracted from any source file, including: C, C++, Python, JavaScript, TypeScript, Go, Rust, Java, Kotlin, Swift, C#, Shell, Perl, Ruby, PHP, Lua, Assembly, and common config formats (YAML, TOML, JSON, Makefile, Kconfig).

### Dependency extraction

| Ecosystem | Files parsed (lock file preferred) |
|---|---|
| Python | `poetry.lock` / `requirements.txt`, `pyproject.toml` |
| Node.js | `package-lock.json` / `package.json` |
| Rust | `Cargo.lock` / `Cargo.toml` |
| Go | `go.sum` / `go.mod` |
| Java (Maven) | `pom.xml` |
| Java (Gradle) | `gradle.lockfile` / `build.gradle` / `build.gradle.kts` |

---

## Installation

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
  --no-hashes                 Skip SHA-256/SHA-1 hashing (faster for large projects)
  --compile-commands PATH     Path to compile_commands.json
  --kernel-build PATH         Path to kernel build directory (Kbuild .cmd files)
  --exclude DIR               Exclude a directory name from scanning (repeatable)
  --workers N                 Number of parallel worker threads (default: 2 × CPU count)
  -q, --quiet                 Suppress all progress output
  -v, --verbose               Show extra detail (license breakdown, per-format timing)
```

---

## Output Files

| File | Format |
|---|---|
| `sbom.spdx.json` | SPDX 2.3 |
| `sbom.spdx3.json` | SPDX 3.0.1 |
| `sbom.cdx.json` | CycloneDX 1.5 |
| `sbom.html` | Interactive HTML dashboard (dark mode, offline charts) |

Use `--format spdx`, `--format cyclonedx`, etc. to generate only what you need.

---

## Architecture

| Module | Responsibility |
|---|---|
| `cli.py` | Entry point — argument parsing, progress display, orchestration |
| `scanner.py` | Parallel directory walk, license extraction, file hashing |
| `manifest_parser.py` | Manifest and lock file parsing for all supported ecosystems |
| `compilation_db.py` | Clang `compile_commands.json` and Kbuild `.cmd` parsing |
| `purl.py` | Canonical PURL generation |
| `vcs.py` | Git metadata extraction |
| `spdx_generator.py` | SPDX 2.3 JSON output |
| `spdx3_generator.py` | SPDX 3.0.1 JSON-LD output |
| `cyclonedx_generator.py` | CycloneDX 1.5 JSON output |
| `html_generator.py` | Self-contained interactive HTML report |
