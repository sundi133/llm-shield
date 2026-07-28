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
    """A quoted or float nav_order sorts against integers unpredictably."""
    data = yaml.safe_load(_front_matter(path))
    if "nav_order" in data:
        assert isinstance(data["nav_order"], int), (
            f"{path.relative_to(DOCS)} has nav_order="
            f"{data['nav_order']!r} ({type(data['nav_order']).__name__}); "
            "it must be a bare integer"
        )


def test_the_page_that_shipped_invisible_is_covered():
    """Regression pin for the specific break."""
    page = DOCS / "non-human-identity.md"
    assert page.exists(), "non-human-identity.md moved — update this pin"
    data = yaml.safe_load(_front_matter(page))
    assert data.get("permalink") == "/non-human-identity/"
    assert isinstance(data.get("nav_order"), int), (
        "without a valid integer nav_order the NHI page has no navbar entry"
    )
