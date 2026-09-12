"""Regression tests for the documentation checker; only temporary fixtures are written."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "check_docs", Path(__file__).resolve().parents[1] / "tools" / "check_docs.py")
DOCS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DOCS)


class DocumentationChecks(unittest.TestCase):
    def run_check(self, files):
        with tempfile.TemporaryDirectory(prefix="vordr-docs-test-") as folder:
            root = Path(folder)
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            return DOCS.check(root)[1]

    def test_valid_links_and_code_examples(self):
        self.assertEqual([], self.run_check({
            "README.md": "# Start\n[Guide](docs/guide.md#hello-world)\n"
                         "[Outside](https://example.test/missing)\n"
                         "```text\n[Not a link](missing.md)\n```\n",
            "docs/guide.md": "# Hello, world!\n[Home](../README.md#start)\n",
        }))

    def test_missing_file_and_anchor(self):
        issues = self.run_check({"README.md": "# Start\n[Bad](missing.md)\n[Bad](#absent)\n"})
        self.assertEqual(2, len(issues))
        self.assertTrue(any("missing target" in x for x in issues))
        self.assertTrue(any("missing anchor" in x for x in issues))

    def test_duplicate_unclosed_and_control(self):
        issues = self.run_check({"README.md": "# Same\n# Same\n\x0b\n```text\n"})
        self.assertEqual(3, len(issues))

    def test_html_and_encoded_path(self):
        self.assertEqual([], self.run_check({
            "README.md": "[Page](docs/a%20b.html#here)",
            "docs/a b.html": '<h1 id="here">Page</h1><a href="../README.md">Home</a>',
        }))

    def test_outside_repository(self):
        issues = self.run_check({"README.md": "[Bad](../outside.md)"})
        self.assertTrue(any("escapes repository" in x for x in issues))


if __name__ == "__main__":
    unittest.main()
