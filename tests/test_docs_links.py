"""Internal doc links must resolve on the published site, not just on GitHub.

The docs site is Jekyll with explicit `permalink:` on every page. A link
written as a relative filename resolves *underneath* the linking page's
permalink:

    page   permalink: /langchain-quickstart/
    link   [runbook](role-binding-runbook.md)
    result /langchain-quickstart/role-binding-runbook.md   -> 404

It looks right in an editor, it works on GitHub, and it is broken for every
reader on the site. That is the worst combination for catching it by eye, and
it had accumulated 45 times before this test existed.

Two rules, both checkable:

  1. A doc must not link to another doc by relative filename. Use the target's
     permalink.
  2. A page-to-page link must point at a page that actually publishes — a file
     with no front matter is copied verbatim by Jekyll and has no URL.
"""
import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parent.parent / "docs"

#: Links of the form ](something.md) or ](something.md#anchor).
_MD_LINK = re.compile(r"\]\(([a-zA-Z0-9._-]+\.md)(#[^)]*)?\)")

#: Links to a site-absolute permalink: ](/foo/) or ](/foo/#anchor).
_PERMALINK_LINK = re.compile(r"\]\((/[a-zA-Z0-9._/-]*/)(#[^)]*)?\)")

_FRONT_MATTER = re.compile(r"\A---\n(.*?)\n---\n", re.S)
_PERMALINK = re.compile(r"^permalink:\s*(\S+)", re.M)


#: Jekyll's own directories, not content.
_SKIP_DIRS = {"_includes", "_layouts", "_sass", "_site", "_data"}


def _pages():
    """Every content page, INCLUDING subdirectories.

    docs/registry/index.md publishes /registry/. A top-level-only glob misses
    it and then reports every link to /registry/ as dead — the test's own first
    false positive, which is worth remembering: a link checker that is wrong is
    worse than none, because the fix is to delete the working link.
    """
    return sorted(f for f in DOCS.rglob("*.md")
                  if not any(part in _SKIP_DIRS for part in f.parts))


def _permalinks() -> dict:
    """{permalink: filename} for every doc that publishes."""
    out = {}
    for f in _pages():
        m = _PERMALINK.search(f.read_text())
        if m:
            out[m.group(1).strip().rstrip("/") + "/"] = f.name
    return out


def test_there_are_docs_to_check():
    """Guard the guard: a bad glob would make everything below vacuously pass."""
    assert len(_pages()) > 40, f"only found {len(_pages())} docs — check the glob"


@pytest.mark.parametrize("path", _pages(), ids=lambda p: str(p.relative_to(DOCS)))
def test_no_relative_md_links(path: Path):
    """Relative filenames 404 on the site. Link by permalink instead."""
    offenders = []
    for i, line in enumerate(path.read_text().split("\n"), 1):
        for m in _MD_LINK.finditer(line):
            offenders.append(f"{path.relative_to(DOCS)}:{i} -> {m.group(1)}")
    assert not offenders, (
        "link by permalink, not filename — these resolve under the linking "
        "page's URL and 404:\n  " + "\n  ".join(offenders))


@pytest.mark.parametrize("path", _pages(), ids=lambda p: str(p.relative_to(DOCS)))
def test_permalink_links_point_at_a_real_page(path: Path):
    """A link to /foo/ must correspond to a doc whose permalink is /foo/.

    Catches the rename case: the page moves, the link keeps pointing at a URL
    nothing serves any more.
    """
    known = _permalinks()
    # Site sections that are not generated from docs/*.md.
    external_prefixes = ("/assets/", "/api/", "/v1/")
    offenders = []
    for i, line in enumerate(path.read_text().split("\n"), 1):
        for m in _PERMALINK_LINK.finditer(line):
            target = m.group(1)
            if target.startswith(external_prefixes) or target == "/":
                continue
            if target not in known:
                offenders.append(f"{path.relative_to(DOCS)}:{i} -> {target}")
    assert not offenders, (
        "no doc publishes these permalinks:\n  " + "\n  ".join(offenders))


def test_every_linked_page_publishes():
    """A doc with no front matter is a static file, not a page.

    Jekyll copies it verbatim and it has no URL, so any link to it 404s. If a
    doc is worth linking from a published page, it needs front matter.
    """
    unpublished = [f.name for f in _pages()
                   if not _FRONT_MATTER.match(f.read_text())]
    linked = set(_permalinks().values())
    broken = [n for n in unpublished if n in linked]
    assert not broken, f"linked but unpublished: {broken}"
