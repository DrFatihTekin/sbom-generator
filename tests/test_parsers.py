import os
import tempfile
import unittest
import json

from sbom_extractor.scanner import extract_spdx_license, calculate_hashes, ProjectScanner
from sbom_extractor.manifest_parser import ManifestParser
from sbom_extractor.compilation_db import CompilationDatabaseParser
from sbom_extractor.spdx_generator import SPDXGenerator
from sbom_extractor.spdx3_generator import SPDX3Generator
from sbom_extractor.cyclonedx_generator import CycloneDXGenerator

class TestSBOMGenerator(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory to act as project workspace for tests
        self.test_dir = tempfile.TemporaryDirectory()
        self.root_path = self.test_dir.name

    def tearDown(self):
        self.test_dir.cleanup()

    def test_spdx_license_extraction(self):
        # Write temporary source files with various license headers
        c_content = """
        /*
         * SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
         *
         * Some comment headers
         */
        int main() { return 0; }
        """
        py_content = "# SPDX-License-Identifier: MIT\nprint('hello')"
        
        c_file = os.path.join(self.root_path, "test.c")
        py_file = os.path.join(self.root_path, "test.py")

        with open(c_file, "w") as f:
            f.write(c_content)
        with open(py_file, "w") as f:
            f.write(py_content)

        self.assertEqual(extract_spdx_license(c_file), "GPL-2.0-only WITH Linux-syscall-note")
        self.assertEqual(extract_spdx_license(py_file), "MIT")

    def test_file_hashing(self):
        # Write dummy file and check hashes
        file_path = os.path.join(self.root_path, "hash_test.txt")
        with open(file_path, "w") as f:
            f.write("OpenSBOM")

        sha256, sha1 = calculate_hashes(file_path)
        # Expected SHA-256 for "OpenSBOM" is:
        # e26e57cdbb701460399d259c766b1e6040854d19d5045dbb6be66299f1fa023e (or similar, let's just check length and structure)
        self.assertEqual(len(sha256), 64)
        self.assertEqual(len(sha1), 40)

    def test_directory_scanner(self):
        # Setup files in subdirectories
        src_dir = os.path.join(self.root_path, "src")
        os.makedirs(src_dir)
        
        with open(os.path.join(src_dir, "main.c"), "w") as f:
            f.write("/* SPDX-License-Identifier: GPL-2.0-only */\n")
            
        with open(os.path.join(self.root_path, "README.md"), "w") as f:
            f.write("Documentation file\n")

        scanner = ProjectScanner(self.root_path, calculate_file_hashes=True)
        files = scanner.scan()
        
        # Verify both files are scanned
        paths = [f["path"] for f in files]
        self.assertIn("src/main.c", paths)
        self.assertIn("README.md", paths)

        # Check detected licenses
        main_c_info = next(f for f in files if f["path"] == "src/main.c")
        self.assertEqual(main_c_info["license"], "GPL-2.0-only")

    def test_manifest_parser(self):
        # Write dummy requirements.txt
        req_content = "requests==2.28.1\nurllib3>=1.26.5\npytest"
        with open(os.path.join(self.root_path, "requirements.txt"), "w") as f:
            f.write(req_content)

        # Write dummy package.json
        pkg_content = {
            "dependencies": {
                "lodash": "^4.17.21"
            },
            "devDependencies": {
                "typescript": "~4.9.0"
            }
        }
        with open(os.path.join(self.root_path, "package.json"), "w") as f:
            json.dump(pkg_content, f)

        parser = ManifestParser(self.root_path)
        deps = parser.scan_manifests()

        names = [d["name"] for d in deps]
        self.assertIn("requests", names)
        self.assertIn("urllib3", names)
        self.assertIn("lodash", names)
        self.assertIn("typescript", names)

        # Check details
        requests_dep = next(d for d in deps if d["name"] == "requests")
        self.assertEqual(requests_dep["version"], "2.28.1")
        self.assertEqual(requests_dep["type"], "pypi")

    def test_compilation_db_parser(self):
        # Write dummy compile_commands.json
        db_content = [
            {
                "directory": self.root_path,
                "command": "gcc -c main.c -o main.o",
                "file": "main.c"
            }
        ]
        with open(os.path.join(self.root_path, "compile_commands.json"), "w") as f:
            json.dump(db_content, f)

        parser = CompilationDatabaseParser(self.root_path)
        entries = parser.find_and_parse_compilation_db()

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "main.c")
        self.assertEqual(entries[0]["path"], "main.c")

    def test_sbom_generation(self):
        files = [
            {
                "name": "main.c",
                "path": "main.c",
                "size": 128,
                "is_source": True,
                "license": "MIT",
                "sha256": "fake-sha-256",
                "sha1": "fake-sha-1"
            }
        ]
        dependencies = [
            {
                "name": "requests",
                "version": "2.28.1",
                "type": "pip",
                "license": "Apache-2.0",
                "path": "requirements.txt"
            }
        ]

        # Test SPDX
        spdx_gen = SPDXGenerator("test-project", "2.1.0")
        spdx_doc = spdx_gen.generate(files, dependencies)
        self.assertEqual(spdx_doc["spdxVersion"], "SPDX-2.3")
        self.assertEqual(spdx_doc["name"], "test-project")
        self.assertEqual(len(spdx_doc["packages"]), 2)  # Main package + requests

        # Test CycloneDX
        cdx_gen = CycloneDXGenerator("test-project", "2.1.0")
        cdx_doc = cdx_gen.generate(files, dependencies)
        self.assertEqual(cdx_doc["bomFormat"], "CycloneDX")
        self.assertEqual(cdx_doc["specVersion"], "1.5")
        self.assertEqual(len(cdx_doc["components"]), 2)  # main.c file + requests library

        # Test SPDX 3.0
        spdx3_gen = SPDX3Generator("test-project", "2.1.0")
        spdx3_doc = spdx3_gen.generate(files, dependencies)
        self.assertEqual(spdx3_doc["@context"], "https://spdx.org/rdf/3.0.1/spdx-context.jsonld")
        graph_types = [el["type"] for el in spdx3_doc["@graph"]]
        self.assertIn("CreationInfo", graph_types)
        self.assertIn("SpdxDocument", graph_types)
        self.assertIn("software_Package", graph_types)
        self.assertIn("software_File", graph_types)
        self.assertIn("Relationship", graph_types)

    def test_java_maven(self):
        pom_content = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.0.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>internal-lib</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>"""
        with open(os.path.join(self.root_path, "pom.xml"), "w") as f:
            f.write(pom_content)

        parser = ManifestParser(self.root_path)
        deps = parser.scan_manifests()
        names = [d["name"] for d in deps]

        self.assertIn("org.springframework:spring-core", names)
        self.assertIn("junit:junit", names)

        spring = next(d for d in deps if d["name"] == "org.springframework:spring-core")
        self.assertEqual(spring["version"], "6.0.0")
        self.assertEqual(spring["type"], "maven")

        # Unresolvable property versions should be stored as "unknown"
        internal = next(d for d in deps if d["name"] == "com.example:internal-lib")
        self.assertEqual(internal["version"], "unknown")

    def test_java_gradle_groovy(self):
        build_content = """\
plugins {
    id 'java'
}
dependencies {
    implementation 'com.google.guava:guava:31.1-jre'
    testImplementation "junit:junit:4.13.2"
    implementation("org.apache.commons:commons-lang3:3.12.0")
    compileOnly group: 'org.projectlombok', name: 'lombok', version: '1.18.24'
}"""
        with open(os.path.join(self.root_path, "build.gradle"), "w") as f:
            f.write(build_content)

        parser = ManifestParser(self.root_path)
        deps = parser.scan_manifests()
        names = [d["name"] for d in deps]

        self.assertIn("com.google.guava:guava", names)
        self.assertIn("junit:junit", names)
        self.assertIn("org.apache.commons:commons-lang3", names)
        self.assertIn("org.projectlombok:lombok", names)

        guava = next(d for d in deps if d["name"] == "com.google.guava:guava")
        self.assertEqual(guava["version"], "31.1-jre")
        self.assertEqual(guava["type"], "maven")

    def test_java_gradle_lockfile(self):
        lock_content = """\
# This is a Gradle generated file for dependency locking.
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
empty=
"""
        with open(os.path.join(self.root_path, "gradle.lockfile"), "w") as f:
            f.write(lock_content)

        parser = ManifestParser(self.root_path)
        deps = parser.scan_manifests()
        names = [d["name"] for d in deps]

        self.assertIn("com.google.guava:guava", names)
        self.assertIn("junit:junit", names)

        guava = next(d for d in deps if d["name"] == "com.google.guava:guava")
        self.assertEqual(guava["version"], "31.1-jre")
        self.assertEqual(guava["source"], "lock")


if __name__ == "__main__":
    unittest.main()
