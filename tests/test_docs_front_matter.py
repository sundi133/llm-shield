"""Every docs page's front matter must parse as YAML.

The docs site build does NOT fail on a malformed front matter block. Jekyll
logs `YAML Exception reading <file>` and carries on, treating the page as a
static file: no layout, no permalink, no nav entry. The workflow goes green,
Pages deploys, and the page is simply absent.

That is how docs/non-human-identity.md shipped invisible. Removing an em dash
from the description left a bare colon in an unquoted scalar:

    description: How Shield identifies and authorizes agents: workload ...
                                                            ^ breaks YAML

`nav_order` is checked too, because a non-integer sorts unpredictably against
the integers on every other page rather than erroring.
"""
import re
from pathlib import Path

import pytest
import yaml

DOCS = Path(__file__).resolve().parent.parent / "docs"

#: Pages carrying front matter. A file without it is a deliberate static asset
#: (nhi-topology.html is one), so absence is not a failure — only a broken
#: block is.
PAGES = sorted(
    p for p in DOCS.rglob("*.md")
    if p.read_text(encoding="utf-8").startswith("---\n")
)


def _front_matter(path: Path) -> str:
    m = re.match(r"^---\n(.*?)\n---\n", path.read_text(encoding="utf-8"), re.S)
    assert m, f"{path.name} starts with --- but has no closing delimiter"
    return m.group(1)


def test_there_are_pages_to_check():
    """Guard the guard: a bad glob would make every test below vacuously pass."""
    assert len(PAGES) > 40, f"only found {len(PAGES)} docs pages — check the glob"


@pytest.mark.parametrize("path", PAGES, ids=lambda p: p.name)
def test_front_matter_is_valid_yaml(path):
    try:
        data = yaml.safe_load(_front_matter(path))
    except yaml.YAMLError as e:
        pytest.fail(
            f"{path.relative_to(DOCS)} has invalid front matter, so Jekyll will "
            f"drop it from the site silently:\n  {str(e).splitlines()[0]}\n\n"
            "Most often an unquoted value containing ': '. Wrap the value in "
            'double quotes.'
        )
    assert isinstance(data, dict), (
        f"{path.relative_to(DOCS)} front matter parsed as {type(data).__name__}, "
        "not a mapping"
    )


@pytest.mark.parametrize("path", PAGES, ids=lambda p: p.name)
def test_nav_order_is_an_integer(path):
    """Only reached if _data/navigation.yml goes missing, but keep it sane.

    The sidebar does NOT use nav_order: the override at
    _includes/components/site_nav.html renders _data/navigation.yml instead, and
    falls back to the theme's auto nav only when that file is absent. A quoted
    or float nav_order would sort unpredictably against the integers on every
    other page in that fallback.
    """
    data = yaml.safe_load(_front_matter(path))
    if "nav_order" in data:
        assert isinstance(data["nav_order"], int), (
            f"{path.relative_to(DOCS)} has nav_order="
            f"{data['nav_order']!r} ({type(data['nav_order']).__name__}); "
            "it must be a bare integer"
        )


def _nav_items() -> list:
    nav = yaml.safe_load((DOCS / "_data" / "navigation.yml").read_text(encoding="utf-8"))
    return [(g.get("title", "?"), i["title"], i["url"])
            for g in nav["groups"] for i in g["items"]]


def _published_urls() -> set:
    """Every URL the built site actually serves."""
    urls = {"/"}
    for p in DOCS.rglob("*.md"):
        src = p.read_text(encoding="utf-8")
        if not src.startswith("---\n"):
            continue
        fm = yaml.safe_load(_front_matter(p)) or {}
        if fm.get("permalink"):
            urls.add(fm["permalink"])
    # Files with no front matter are copied verbatim and served at their path.
    for p in DOCS.rglob("*.html"):
        if not p.read_text(encoding="utf-8").startswith("---\n"):
            urls.add("/" + p.relative_to(DOCS).as_posix())
    return urls


@pytest.mark.parametrize("group,title,url", _nav_items(),
                         ids=lambda v: v if isinstance(v, str) else str(v))
def test_every_sidebar_link_resolves(group, title, url):
    """A sidebar entry pointing at nothing is a 404 the build will not catch."""
    assert url in _published_urls(), (
        f"sidebar entry {title!r} (group {group!r}) points at {url}, which no "
        "page publishes. Check the permalink in the page's front matter."
    )


def test_the_nhi_page_is_in_the_sidebar():
    """Regression pin, and the check that actually matters.

    Two separate things had to be true for this page to appear, and each failed
    on its own: the front matter had to parse (a bare colon broke it, so the
    page 404'd), and the page had to be listed in _data/navigation.yml (it was
    not, so nothing linked it even once it built). nav_order is irrelevant to
    both.
    """
    page = DOCS / "non-human-identity.md"
    assert page.exists(), "non-human-identity.md moved — update this pin"
    assert yaml.safe_load(_front_matter(page)).get("permalink") == "/non-human-identity/"
    assert "/non-human-identity/" in [u for _, _, u in _nav_items()], (
        "the NHI page builds but is not in _data/navigation.yml, so it has no "
        "sidebar entry — which is exactly how it shipped invisible"
    )
