"""Exercise the actual manifest writer without building an MSI or publishing."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


GENERATOR = Path(__file__).resolve().parents[1] / "tools" / "make_winget.ps1"


@unittest.skipUnless(shutil.which("powershell"), "Windows PowerShell required")
class ManifestEncodingTests(unittest.TestCase):
    def test_writer_uses_bomless_utf8_and_crlf(self):
        # Extract only the writer's function AST: never run MSI discovery or COM.
        script = r'''
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:VORDR_WINGET_GENERATOR, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Generator has syntax errors' }
$writer = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Write-Manifest'
}, $true)
if (-not $writer) { throw 'Write-Manifest not found' }
. ([scriptblock]::Create($writer.Extent.Text))
$accent = [char]0xE9
Write-Manifest (Join-Path $env:VORDR_WINGET_TEST_OUT 'lf.yaml') "Name: caf${accent}`nVersion: 1"
Write-Manifest (Join-Path $env:VORDR_WINGET_TEST_OUT 'crlf.yaml') "Name: caf${accent}`r`nVersion: 1"
Write-Manifest (Join-Path $env:VORDR_WINGET_TEST_OUT 'mixed.yaml') "A: 1`r`nB: 2`nC: 3"
'''
        with tempfile.TemporaryDirectory(prefix="vordr-winget-test-") as folder:
            env = dict(os.environ, VORDR_WINGET_GENERATOR=str(GENERATOR),
                       VORDR_WINGET_TEST_OUT=folder)
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            expected = {
                "lf.yaml": "Name: caf\u00e9\r\nVersion: 1\r\n",
                "crlf.yaml": "Name: caf\u00e9\r\nVersion: 1\r\n",
                "mixed.yaml": "A: 1\r\nB: 2\r\nC: 3\r\n",
            }
            for name, text in expected.items():
                with self.subTest(name=name):
                    self.assertEqual((Path(folder) / name).read_bytes(), text.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
