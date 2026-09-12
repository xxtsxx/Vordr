"""Check repository documentation without network access or third-party packages.

Scope: root Markdown, docs/ Markdown and HTML, and Markdown issue templates.
Checks our inline Markdown links (not a complete CommonMark parser), HTML links,
local anchors, duplicate headings, fenced blocks, and unexpected control bytes.
External URLs and links inside code examples are deliberately not fetched.
"""
import argparse
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import unicodedata
from urllib.parse import unquote, urlsplit


class HtmlLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.anchors = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.anchors.add(attrs["id"])
        for name in ("href", "src"):
            if name in attrs:
                self.links.append(attrs[name])


def slug(text):
    text = unescape(re.sub(r"<[^>]*>", "", text)).lower().strip()
    text = "".join(c for c in text if c in "-_ " or
                   unicodedata.category(c)[0] in "LN")
    return text.replace(" ", "-")


def parse(path):
    text = path.read_text(encoding="utf-8-sig")
    errors = []
    if any(ord(c) < 32 and c not in "\n\r\t" for c in text):
        errors.append("unexpected control character")
    if path.suffix.lower() == ".html":
        parser = HtmlLinks()
        parser.feed(text)
        return parser.links, parser.anchors, errors
    anchors = set()
    content = []
    fence = None
    for line in text.splitlines():
        mark = re.match(r"^\s{0,3}(`{3,}|~{3,})(.*)$", line)
        if mark:
            run, tail = mark.groups()
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence) and not tail.strip():
                fence = None
            continue
        if fence is not None:
            continue
        heading = re.match(r"^#{1,6}\s+(.+?)(?:\s+#+)?$", line)
        if heading:
            anchor = slug(heading[1])
            if anchor in anchors:
                errors.append("duplicate heading: " + heading[1])
            anchors.add(anchor)
        content.append(line)
    if fence is not None:
        errors.append("unclosed fenced code block")
    prose = re.sub(r"<!--.*?-->", "", "\n".join(content), flags=re.S)
    links = []
    for match in re.finditer(r"!?\[[^\]]*\]\((<[^>]+>|[^\s)]+)(?:\s+\"[^\"]*\")?\)", prose):
        links.append(match[1].strip("<>"))
    parser = HtmlLinks()
    parser.feed(prose)
    links.extend(parser.links)
    anchors.update(parser.anchors)
    return links, anchors, errors


def check(root):
    root = root.resolve()
    files = set(root.glob("*.md"))
    for directory in (root / "docs", root / ".github" / "ISSUE_TEMPLATE"):
        if directory.exists():
            files.update(p for p in directory.rglob("*") if p.suffix.lower() in (".md", ".html"))
    cache = {}
    errors = []
    for path in sorted(files):
        try:
            cache[path] = parse(path)
        except (OSError, UnicodeError) as exc:
            errors.append(f"{path.relative_to(root)}: {exc}")
    for path, (links, _, issues) in cache.items():
        name = path.relative_to(root)
        errors.extend(f"{name}: {issue}" for issue in issues)
        for link in links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            target = (path.parent / unquote(url.path)).resolve() if url.path else path
            if not target.is_relative_to(root):
                errors.append(f"{name}: link escapes repository: {link}")
            elif not target.exists():
                errors.append(f"{name}: missing target: {link}")
            elif url.fragment and target.suffix.lower() in (".md", ".html"):
                if target not in cache:
                    cache_value = parse(target)
                else:
                    cache_value = cache[target]
                if unquote(url.fragment) not in cache_value[1]:
                    errors.append(f"{name}: missing anchor: {link}")
    return len(files), errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    count, errors = check(args.root)
    for error in errors:
        print(error)
    print(f"docs: {count} files checked, {len(errors)} error(s)")
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
