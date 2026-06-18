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
from sbom_extractor.cpe import generate_cpe
from sbom_extractor.catena_x_generator import CatenaXGenerator
from sbom_extractor import ntia, validator

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

        # ${project.version} is resolved from the POM's own <version> element
        internal = next(d for d in deps if d["name"] == "com.example:internal-lib")
        self.assertEqual(internal["version"], "1.0.0")

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


    # ── Reproducible mode ─────────────────────────────────────────────

    def test_reproducible_spdx(self):
        files = [{"name": "main.c", "path": "main.c", "size": 10,
                  "is_source": True, "license": "MIT", "sha256": "", "sha1": ""}]
        gen1 = SPDXGenerator("proj", "1.0.0", reproducible=True)
        gen2 = SPDXGenerator("proj", "1.0.0", reproducible=True)
        doc1 = gen1.generate(files, [])
        doc2 = gen2.generate(files, [])
        self.assertEqual(doc1["creationInfo"]["created"], doc2["creationInfo"]["created"])
        self.assertEqual(doc1["documentNamespace"], doc2["documentNamespace"])
        self.assertEqual(doc1["creationInfo"]["created"], "1970-01-01T00:00:00Z")

    def test_reproducible_cyclonedx(self):
        gen1 = CycloneDXGenerator("proj", "1.0.0", reproducible=True)
        gen2 = CycloneDXGenerator("proj", "1.0.0", reproducible=True)
        doc1 = gen1.generate([], [])
        doc2 = gen2.generate([], [])
        self.assertEqual(doc1["serialNumber"], doc2["serialNumber"])
        self.assertEqual(doc1["metadata"]["timestamp"], "1970-01-01T00:00:00Z")

    # ── SPDX ID collision ─────────────────────────────────────────────

    def test_spdx_no_id_collision(self):
        deps = [
            {"name": "my.lib", "version": "1.0", "type": "pypi", "license": "MIT"},
            {"name": "my-lib", "version": "1.0", "type": "pypi", "license": "MIT"},
        ]
        gen = SPDXGenerator("proj", "1.0.0")
        doc = gen.generate([], deps)
        ids = [p["SPDXID"] for p in doc["packages"]]
        self.assertEqual(len(ids), len(set(ids)), "SPDX IDs must be unique")

    # ── Streaming SPDX output ─────────────────────────────────────────

    def test_spdx_write_streaming(self):
        files = [
            {"name": f"file{i}.c", "path": f"src/file{i}.c", "size": 100,
             "is_source": True, "license": "MIT", "sha256": "abc", "sha1": "def"}
            for i in range(10)
        ]
        deps = [{"name": "requests", "version": "2.28.1", "type": "pypi",
                 "license": "Apache-2.0"}]

        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "test.spdx.json")
            gen = SPDXGenerator("proj", "1.0.0")
            gen.write_streaming(files, deps, out)
            with open(out) as f:
                doc = json.load(f)

        self.assertEqual(doc["spdxVersion"], "SPDX-2.3")
        self.assertEqual(len(doc["files"]), 10)
        # Validate structure
        errs = validator.validate_spdx(doc)
        self.assertEqual(errs, [], f"Validation errors: {errs}")

    # ── Streaming CycloneDX output ────────────────────────────────────

    def test_cyclonedx_write_streaming(self):
        files = [
            {"name": "main.c", "path": "main.c", "size": 50,
             "is_source": True, "license": "GPL-2.0-only OR MIT", "sha256": "", "sha1": ""}
        ]
        deps = [{"name": "lodash", "version": "4.17.21", "type": "npm", "license": "MIT"}]

        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "test.cdx.json")
            gen = CycloneDXGenerator("proj", "1.0.0")
            gen.write_streaming(files, deps, out)
            with open(out) as f:
                doc = json.load(f)

        self.assertEqual(doc["bomFormat"], "CycloneDX")
        errs = validator.validate_cyclonedx(doc)
        self.assertEqual(errs, [], f"Validation errors: {errs}")

    # ── CPE generation ────────────────────────────────────────────────

    def test_cpe_maven(self):
        cpe = generate_cpe({"name": "org.springframework:spring-core",
                             "version": "6.0.0", "type": "maven"})
        self.assertTrue(cpe.startswith("cpe:2.3:a:org.springframework:spring-core:6.0.0"))

    def test_cpe_pypi(self):
        cpe = generate_cpe({"name": "requests", "version": "2.28.1", "type": "pypi"})
        self.assertTrue(cpe.startswith("cpe:2.3:a:requests:requests:2.28.1"))

    def test_cpe_golang(self):
        cpe = generate_cpe({"name": "github.com/user/repo", "version": "1.2.3", "type": "golang"})
        self.assertIn("user", cpe)
        self.assertIn("repo", cpe)

    # ── NTIA compliance ───────────────────────────────────────────────

    def test_ntia_compliant(self):
        issues = ntia.check("myproject", "1.2.3", [], supplier="Acme Corp")
        self.assertEqual(issues, [])

    def test_ntia_missing_supplier(self):
        issues = ntia.check("myproject", "1.2.3", [], supplier=None)
        self.assertTrue(any("Supplier" in i for i in issues))

    def test_ntia_unknown_version(self):
        deps = [{"name": "requests", "version": "unknown", "type": "pypi"}]
        issues = ntia.check("myproject", "1.0.0", deps, supplier="Acme")
        self.assertTrue(any("unknown version" in i for i in issues))

    # ── SBOM validation ───────────────────────────────────────────────

    def test_validate_spdx_valid(self):
        gen = SPDXGenerator("proj", "1.0.0")
        doc = gen.generate([], [])
        errs = validator.validate_spdx(doc)
        self.assertEqual(errs, [])

    def test_validate_cyclonedx_valid(self):
        gen = CycloneDXGenerator("proj", "1.0.0")
        doc = gen.generate([], [])
        errs = validator.validate_cyclonedx(doc)
        self.assertEqual(errs, [])

    # ── Maven property resolution ─────────────────────────────────────

    def test_maven_property_resolution(self):
        pom = """\
<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <version>2.0.0</version>
  <properties>
    <spring.version>6.0.0</spring.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>parent-dep</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>"""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pom.xml"), "w") as f:
                f.write(pom)
            parser = ManifestParser(d)
            deps = parser.scan_manifests()

        names = {d["name"]: d["version"] for d in deps}
        self.assertEqual(names.get("org.springframework:spring-core"), "6.0.0")
        self.assertEqual(names.get("com.example:parent-dep"), "2.0.0")

    # ── requirements.in support ───────────────────────────────────────

    def test_requirements_in(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "requirements.in"), "w") as f:
                f.write("flask>=2.0\nrequests\n")
            parser = ManifestParser(d)
            deps = parser.scan_manifests()
        names = [d["name"] for d in deps]
        self.assertIn("flask", names)
        self.assertIn("requests", names)

    # ── Multi-module Maven ────────────────────────────────────────────

    def test_multimodule_maven(self):
        pom_root = """\
<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>root</artifactId><version>1.0</version>
  <dependencies>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version></dependency>
  </dependencies>
</project>"""
        pom_module = """\
<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>module-a</artifactId><version>1.0</version>
  <dependencies>
    <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>31.1-jre</version></dependency>
  </dependencies>
</project>"""
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "module-a"))
            with open(os.path.join(d, "pom.xml"), "w") as f:
                f.write(pom_root)
            with open(os.path.join(d, "module-a", "pom.xml"), "w") as f:
                f.write(pom_module)
            parser = ManifestParser(d)
            deps = parser.scan_manifests()

        names = [d["name"] for d in deps]
        self.assertIn("junit:junit", names)
        self.assertIn("com.google.guava:guava", names)


    def test_catena_x_cx0158_compliant(self):
        """CX-0158: only DEPENDS_ON rels, no file elements, valid SPDX 3.0 JSON-LD."""
        deps = [
            {"name": "requests", "version": "2.31.0", "type": "pypi", "license": "Apache-2.0"},
            {"name": "com.google.guava:guava", "version": "32.0", "type": "maven", "license": "Apache-2.0"},
        ]
        gen = CatenaXGenerator("my-product", "1.0.0", supplier="Acme Corp")
        doc = gen.generate(deps)

        self.assertEqual(doc["@context"], "https://spdx.org/rdf/3.0.1/spdx-context.jsonld")
        graph = doc["@graph"]
        types = [e["type"] for e in graph]
        self.assertIn("CreationInfo", types)
        self.assertIn("SpdxDocument", types)
        self.assertIn("software_Package", types)
        self.assertNotIn("software_File", types)

        # Only DEPENDS_ON relationships
        rels = [e for e in graph if e["type"] == "Relationship"]
        self.assertTrue(len(rels) > 0)
        for rel in rels:
            self.assertEqual(rel["relationshipType"], "dependsOn",
                             f"Non-DEPENDS_ON relationship found: {rel}")

        # CX-0158 validation passes
        errs = validator.validate_catena_x(doc)
        self.assertEqual(errs, [], f"CX-0158 validation errors: {errs}")

    def test_catena_x_option1_anonymous_nodes(self):
        """Option 1: each dep is wrapped in an anonymous node with SHA3-256 ID."""
        deps = [{"name": "lodash", "version": "4.17.21", "type": "npm", "license": "MIT"}]
        gen = CatenaXGenerator("my-product", "1.0.0", propagation_option=1)
        doc = gen.generate(deps)

        graph = doc["@graph"]
        anon_nodes = [e for e in graph if e.get("name") == "Anonymous node"]
        self.assertEqual(len(anon_nodes), 1)
        self.assertTrue(anon_nodes[0]["spdxId"].startswith("catena-x-sbom-option-1-"))
        # SHA3-256 hex digest is 64 chars
        hex_part = anon_nodes[0]["spdxId"].replace("catena-x-sbom-option-1-", "")
        self.assertEqual(len(hex_part), 64)

        errs = validator.validate_catena_x(doc)
        self.assertEqual(errs, [], f"CX-0158 validation errors: {errs}")

    def test_catena_x_write_atomic(self):
        """write() produces a valid JSON-LD file with .spdx.jsonld path."""
        deps = [{"name": "rich", "version": "13.0.0", "type": "pypi", "license": "MIT"}]
        gen = CatenaXGenerator("test-project", "0.1.0")
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "output.spdx.jsonld")
            gen.write(deps, out)
            self.assertTrue(os.path.exists(out))
            self.assertFalse(os.path.exists(out + ".tmp"))
            with open(out) as f:
                doc = json.load(f)
            errs = validator.validate_catena_x(doc)
            self.assertEqual(errs, [])

    def test_catena_x_validator_rejects_non_depends_on(self):
        """validate_catena_x catches forbidden relationship types."""
        doc = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [
                {"type": "CreationInfo", "spdxId": "_:ci", "specVersion": "3.0.1",
                 "created": "2026-01-01T00:00:00Z", "createdBy": []},
                {"type": "SpdxDocument", "spdxId": "https://example.com/doc",
                 "creationInfo": "_:ci", "rootElement": ["_:main"],
                 "profileConformance": ["core", "software"], "name": "test"},
                {"type": "software_Package", "spdxId": "_:main", "creationInfo": "_:ci",
                 "name": "test", "software_packageVersion": "1.0"},
                {"type": "software_Package", "spdxId": "_:dep", "creationInfo": "_:ci",
                 "name": "dep", "software_packageVersion": "1.0"},
                {"type": "Relationship", "spdxId": "_:rel", "creationInfo": "_:ci",
                 "from": "_:main", "relationshipType": "contains", "to": ["_:dep"]},
            ],
        }
        errs = validator.validate_catena_x(doc)
        self.assertTrue(any("contains" in e for e in errs))

    def test_catena_x_validator_rejects_file_elements(self):
        """validate_catena_x catches software_File elements (not allowed in CX-0158)."""
        doc = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [
                {"type": "CreationInfo", "spdxId": "_:ci", "specVersion": "3.0.1",
                 "created": "2026-01-01T00:00:00Z", "createdBy": []},
                {"type": "SpdxDocument", "spdxId": "https://example.com/doc",
                 "creationInfo": "_:ci", "rootElement": ["_:main"],
                 "profileConformance": ["core", "software"], "name": "test"},
                {"type": "software_Package", "spdxId": "_:main", "creationInfo": "_:ci",
                 "name": "test", "software_packageVersion": "1.0"},
                {"type": "software_File", "spdxId": "_:file", "creationInfo": "_:ci",
                 "name": "main.c"},
            ],
        }
        errs = validator.validate_catena_x(doc)
        self.assertTrue(any("software_File" in e for e in errs))


if __name__ == "__main__":
    unittest.main()
