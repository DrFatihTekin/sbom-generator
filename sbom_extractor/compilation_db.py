import os
import json
import re
from typing import Dict, Any, List, Set

class CompilationDatabaseParser:
    """Parser for compile_commands.json and Linux kernel Kbuild .cmd files."""

    def __init__(self, root_dir: str):
        self.root_dir = os.path.abspath(root_dir)

    def find_and_parse_compilation_db(self, db_path: str = None) -> List[Dict[str, Any]]:
        """
        Locate and parse compile_commands.json.
        Returns a list of dictionaries, each containing metadata about a compiled file.
        """
        if not db_path:
            db_path = os.path.join(self.root_dir, "compile_commands.json")

        if not os.path.exists(db_path):
            return []

        try:
            with open(db_path, "r", encoding="utf-8") as f:
                entries = json.load(f)
        except Exception as e:
            print(f"Error reading compilation database {db_path}: {e}")
            return []

        compiled_files = []
        for entry in entries:
            file_path = entry.get("file", "")
            directory = entry.get("directory", self.root_dir)

            if not file_path:
                continue

            # Resolve relative paths relative to the build entry directory
            if not os.path.isabs(file_path):
                abs_path = os.path.abspath(os.path.join(directory, file_path))
            else:
                abs_path = os.path.abspath(file_path)

            # Keep path relative to the root directory for SBOM display
            rel_path = os.path.relpath(abs_path, self.root_dir)

            compiled_files.append({
                "name": os.path.basename(abs_path),
                "absolute_path": abs_path,
                "path": rel_path,
                "directory": directory,
                "command": entry.get("command", entry.get("arguments", ""))
            })

        return compiled_files

    def parse_kernel_cmd_files(self, build_dir: str = None) -> Set[str]:
        """
        Scan a Linux kernel build directory for .cmd files (e.g. .*.cmd).
        Extracts source and header file paths that were used during compilation.
        """
        search_dir = build_dir if build_dir else self.root_dir
        scanned_paths: Set[str] = set()

        if not os.path.exists(search_dir):
            return scanned_paths

        # Match dependencies in Kbuild .cmd files:
        # e.g., dep_init/main.o := \
        #   init/main.c \
        #   include/linux/compiler.h \
        #   ...
        # Also contains absolute paths
        cmd_file_pattern = re.compile(r"^\s*([^\s\\:=]+)\s*\\?$")

        for root, _, files in os.walk(search_dir):
            for file in files:
                if file.endswith(".cmd") and file.startswith("."):
                    cmd_path = os.path.join(root, file)
                    try:
                        with open(cmd_path, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                # We look for lines containing paths. They typically start with whitespace and end with \ or are listed as deps.
                                line = line.strip()
                                if not line or line.startswith("cmd_") or ":=" in line:
                                    continue
                                
                                # Clean up paths (they might have a trailing backslash or space)
                                clean_line = line.rstrip("\\").strip()
                                if clean_line and (clean_line.endswith(".c") or clean_line.endswith(".h") or clean_line.endswith(".S") or clean_line.endswith(".s")):
                                    # Resolve path
                                    if not os.path.isabs(clean_line):
                                        abs_path = os.path.abspath(os.path.join(self.root_dir, clean_line))
                                    else:
                                        abs_path = os.path.abspath(clean_line)
                                    
                                    if os.path.exists(abs_path):
                                        scanned_paths.add(abs_path)
                    except Exception:
                        pass

        return scanned_paths
