#!/usr/bin/env python3
"""Zero-dependency documentation inventory, link/anchor validator, and style linter.

Scans Markdown (.md) and HTML (.html) files across a repository (excluding VCS,
build, dependency, and agent-skill directories), checks internal links, heading
anchors, duplicate headings, unclosed code fences, and control bytes, and
optionally flags hype/weasel-word hotspots (--lint-style).
"""
import argparse
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import unicodedata
from urllib.parse import unquote, urlsplit

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".agents", ".agent", "_agents", "_agent",
    "node_modules", ".venv", "venv", "__pycache__", "bin", "obj",
    "dist", "build", "target", ".tox", ".mypy_cache", ".pytest_cache",
}

HYPE_PATTERNS = [
    (re.compile(r"\b(military[- ]grade|unbreakable|bulletproof|unhackable|100%\s+secure|bank[- ]grade)\b", re.I),
     "hype superlative (replace with concrete cryptographic/engineering specification)"),
    (re.compile(r"\b(blazingly\s+fast|lightning[- ]fast|ultra[- ]secure|rock[- ]solid|world[- ]class)\b", re.I),
     "marketing adjective (replace with measured latency, complexity, or invariant)"),
    (re.compile(r"\b(it\s+should\s+be\s+noted\s+that|in\s+order\s+to\s+ensure\s+that|needless\s+to\s+say|as\s+mentioned\s+earlier)\b", re.I),
     "verbose filler phrase (condense)"),
]


class HtmlScan(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.anchors = set()
        self._in_script_or_style = False
        self.text_chunks = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() in ("script", "style"):
            self._in_script_or_style = True
        d = dict(attrs)
        if d.get("id"):
            self.anchors.add(d["id"])
        if d.get("name"):
            self.anchors.add(d["name"])
        for attr in ("href", "src"):
            if d.get(attr):
                self.links.append(d[attr])

    def handle_endtag(self, tag):
        if tag.lower() in ("script", "style"):
            self._in_script_or_style = False

    def handle_data(self, data):
        if not self._in_script_or_style:
            self.text_chunks.append(data)


def slugify(heading_text: str) -> str:
    cleaned = unescape(re.sub(r"<[^>]*>", "", heading_text)).lower().strip()
    kept = "".join(
        ch for ch in cleaned
        if ch in "-_ " or unicodedata.category(ch)[0] in ("L", "N")
    )
    return kept.replace(" ", "-")


def discover_docs(root: Path):
    found = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts[:-1]):
            continue
        if path.suffix.lower() in (".md", ".html"):
            found.append(path)
    return sorted(found)


def parse_doc(path: Path, lint_style: bool = False):
    text = path.read_text(encoding="utf-8-sig")
    errors = []
    warnings = []
    if any(ord(ch) < 32 and ch not in "\n\r\t" for ch in text):
        errors.append("unexpected control character")

    if path.suffix.lower() == ".html":
        scanner = HtmlScan()
        scanner.feed(text)
        prose_lines = "\n".join(scanner.text_chunks).splitlines()
        if lint_style:
            for idx, line in enumerate(prose_lines, 1):
                for rx, msg in HYPE_PATTERNS:
                    m = rx.search(line)
                    if m:
                        warnings.append(f"html text#{idx} '{m.group(0)}': {msg}")
        return scanner.links, scanner.anchors, len(text.splitlines()), errors, warnings

    anchors = set()
    prose_lines = []
    fence = None
    lines = text.splitlines()
    for lineno, line in enumerate(lines, 1):
        m_fence = re.match(r"^\s{0,3}(`{3,}|~{3,})(.*)$", line)
        if m_fence:
            run, tail = m_fence.groups()
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence) and not tail.strip():
                fence = None
            continue
        if fence is not None:
            continue
        m_head = re.match(r"^#{1,6}\s+(.+?)(?:\s+#+)?$", line)
        if m_head:
            anchor = slugify(m_head.group(1))
            if anchor in anchors:
                errors.append(f"L{lineno}: duplicate heading '{m_head.group(1)}'")
            anchors.add(anchor)
        prose_lines.append((lineno, line))

    if fence is not None:
        errors.append("unclosed fenced code block")

    prose_joined = re.sub(r"<!--.*?-->", "", "\n".join(l for _, l in prose_lines), flags=re.S)
    links = [
        m.group(1).strip("<>")
        for m in re.finditer(r"!?\[[^\]]*\]\((<[^>]+>|[^\s)]+)(?:\s+\"[^\"]*\")?\)", prose_joined)
    ]
    html_inline = HtmlScan()
    html_inline.feed(prose_joined)
    links.extend(html_inline.links)
    anchors.update(html_inline.anchors)

    if lint_style:
        for lineno, line in prose_lines:
            stripped = re.sub(r"`[^`]*`", "", line)
            for rx, msg in HYPE_PATTERNS:
                m = rx.search(stripped)
                if m:
                    warnings.append(f"L{lineno} '{m.group(0)}': {msg}")

    return links, anchors, len(lines), errors, warnings


def audit_repo(root: Path, lint_style: bool = False):
    root = root.resolve()
    files = discover_docs(root)
    parsed = {}
    errors = []
    warnings = []

    for path in files:
        try:
            parsed[path] = parse_doc(path, lint_style=lint_style)
        except (OSError, UnicodeError) as exc:
            errors.append(f"{path.relative_to(root)}: {exc}")

    for path, (links, _, _, doc_errors, doc_warnings) in parsed.items():
        rel = path.relative_to(root)
        errors.extend(f"{rel}: {e}" for e in doc_errors)
        warnings.extend(f"{rel}: {w}" for w in doc_warnings)
        for link in links:
            if link.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            u = urlsplit(link)
            if u.scheme or u.netloc:
                continue
            target = (path.parent / unquote(u.path)).resolve() if u.path else path
            if not target.is_relative_to(root):
                errors.append(f"{rel}: link escapes repository: {link}")
            elif not target.exists():
                errors.append(f"{rel}: missing link target: {link}")
            elif u.fragment and target.suffix.lower() in (".md", ".html"):
                if target not in parsed:
                    t_anchors = parse_doc(target, lint_style=False)[1]
                else:
                    t_anchors = parsed[target][1]
                if unquote(u.fragment) not in t_anchors:
                    errors.append(f"{rel}: missing anchor #{unquote(u.fragment)} in {link}")

    return files, parsed, errors, warnings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root directory")
    ap.add_argument("--lint-style", action="store_true", help="Report hype/filler prose warnings")
    ap.add_argument("--quiet", action="store_true", help="Only print summary and findings")
    args = ap.parse_args()

    files, parsed, errors, warnings = audit_repo(args.root, lint_style=args.lint_style)
    root = args.root.resolve()

    if not args.quiet:
        print(f"=== Documentation Inventory ({len(files)} files under {root}) ===")
        for p in files:
            links, anchors, nlines, d_err, d_warn = parsed.get(p, ([], set(), 0, [], []))
            rel = p.relative_to(root).as_posix()
            print(f"  {rel:<42} {nlines:>5} lines  {len(anchors):>3} headings  {len(links):>3} links")

    if warnings:
        print(f"\n=== Style Advisory ({len(warnings)}) ===")
        for w in warnings:
            print(f"  [style] {w}")

    if errors:
        print(f"\n=== Structural Errors ({len(errors)}) ===", file=sys.stderr)
        for e in errors:
            print(f"  [error] {e}", file=sys.stderr)
        return 1

    print(f"\ndoc_inventory: {len(files)} file(s) checked, 0 structural errors, {len(warnings)} style advisory item(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
