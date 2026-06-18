# OpenSBOM Extractor & Viewer

OpenSBOM Extractor is a Python-based utility designed to analyze and extract Software Bill of Materials (SBOM) metadata from open-source codebases. It is uniquely tailored to support both modern high-level languages and complex, compiled low-level systems like the Linux kernel.

## 🚀 Key Features

*   **Multi-Ecosystem Manifest Scanning:** Auto-detects and extracts third-party package dependencies from:
    *   **Python:** `requirements.txt`
    *   **Node.js/JavaScript:** `package.json`
    *   **Rust:** `Cargo.toml`
    *   **Go:** `go.mod`
*   **Precision C/C++ Build Tracing:**
    *   Supports reading a Clang compilation database (`compile_commands.json`) to pinpoint exactly which files compile into the final binary.
    *   Supports parsing Linux kernel Kbuild `.cmd` files to map header and source file build dependencies accurately.
*   **Source Code License Extraction:** Inspects files to extract embedded `SPDX-License-Identifier` tags (e.g. `GPL-2.0-only` or `MIT`).
*   **Standards Compliant Output:**
    *   **SPDX 2.3** JSON Document
    *   **CycloneDX 1.5** JSON Document
*   **Premium Interactive HTML Dashboard:** Generates a stunning dark-mode HTML interface loaded with SVG-based offline charts, real-time client-side searching, filtering, and deep metadata detail panes.

---

## 📦 Installation

To install the CLI tool locally, run:

```bash
# From the repository root directory
pip install -e .
```

Alternatively, you can run it directly as a Python module without installation:

```bash
python -m sbom_extractor.cli [options] <path_to_project>
```

---

## 🛠️ Usage Examples

### 1. General Directory Scan
Scan a standard project directory (will walk the file tree, extract licenses, and read package manifests):
```bash
sbom-extractor /path/to/my-project -o my-project-sbom
```

### 2. Scanning a Compiled C/C++ Project
Generate compile commands (e.g. via CMake `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .` or Bear) and use it for a high-fidelity SBOM of only the built sources:
```bash
sbom-extractor /path/to/c-project --compile-commands /path/to/c-project/compile_commands.json -o c-project-sbom
```

### 3. Scanning the Linux Kernel (Using `compile_commands.json`)
The Linux kernel provides a native script to generate `compile_commands.json` after compilation.
```bash
cd /path/to/linux-kernel
# Compile the kernel first
make defconfig
make -j$(nproc)
# Generate the compilation database
python3 scripts/clang-tools/gen_compile_commands.py

# Run the OpenSBOM Extractor on the kernel source
sbom-extractor /path/to/linux-kernel --compile-commands /path/to/linux-kernel/compile_commands.json --no-hashes -o linux-kernel-sbom
```
*(Note: `--no-hashes` is highly recommended for projects of the Linux kernel's scale to bypass heavy file hashing operations).*

### 4. Scanning the Linux Kernel (Using Kbuild `.cmd` files)
Alternatively, scan the build directory directly to locate `.cmd` build trace files:
```bash
sbom-extractor /path/to/linux-kernel --kernel-build /path/to/linux-kernel/build-output-dir --no-hashes -o linux-kernel-sbom
```

---

## ⚙️ CLI Command Line Options

```text
positional arguments:
  path                  Path to the project directory to scan

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Base filename for the output SBOM files (default: sbom)
  --format {spdx,cyclonedx,html,all}
                        Output format for the SBOM (default: all)
  --project-name PROJECT_NAME
                        Name of the project (defaults to the directory name)
  --project-version PROJECT_VERSION
                        Version of the project (default: 1.0.0)
  --no-hashes           Skip calculating file SHA-256/SHA-1 hashes (faster scanning)
  --compile-commands COMPILE_COMMANDS
                        Path to compile_commands.json
  --kernel-build KERNEL_BUILD
                        Path to kernel build directory (searches for Kbuild .cmd files)
```

---

## 📂 Output Files Generated

By default, the program outputs three files:
1.  **`sbom.spdx.json`**: An SPDX 2.3 compliant Software Bill of Materials.
2.  **`sbom.cdx.json`**: A CycloneDX 1.5 compliant Software Bill of Materials.
3.  **`sbom.html`**: A fully interactive HTML report detailing the findings.

---

## 💻 Tech Stack & Architecture

The project has no external dependencies. The core architecture uses built-in Python standard libraries:
*   `argparse` for CLI commands.
*   `hashlib` for calculating file fingerprints.
*   `re` for extracting license headers and resolving requirements.
*   `json` for reading config databases and writing output formats.
*   The HTML generator outputs a self-contained HTML page using embedded Javascript and SVG for premium visualization styling.
