"""Static checks on the served web UI (web/index.html).

WHY THIS FILE EXISTS
A stray backspace byte (0x08) sat inside the SQL-mode regex literal in shipped,
deployed code:

    /^\\s*(select|with)<0x08>/i

Someone wrote `\\b` for a word boundary and a shell interpreted it as an escape,
emitting the control character instead of the two characters backslash-b. The
regex then required a literal backspace after "select", so it matched nothing
and EVERY valid query typed in SQL mode was rejected as "That's a question, not
SQL". The page looked completely normal: no console error, no failed request,
valid JavaScript that parsed and ran fine.

Nothing caught it. The UI is a single static asset with no build step, so there
was no linter, bundler, or type checker in its path, and pytest only ever looked
at Python. It was found by clicking the button.

These are deliberately cheap invariants -- they will not catch logic errors, but
they catch the class of defect that is invisible to review and to the eye.
"""

import io
import os
import re

import pytest

UI_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "web", "index.html")


@pytest.fixture(scope="module")
def raw() -> bytes:
    with io.open(UI_PATH, "rb") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def text(raw) -> str:
    return raw.decode("utf-8")


def test_no_stray_control_characters(raw):
    """Tab, newline, and carriage return are legitimate; nothing else is.

    This is the exact check that would have caught the backspace-in-regex bug.
    """
    allowed = {0x09, 0x0A, 0x0D}
    offenders = [
        (i, byte, raw[max(0, i - 50):i + 15])
        for i, byte in enumerate(raw)
        if byte < 0x20 and byte not in allowed
    ]
    assert not offenders, "control characters found in web/index.html: " + "; ".join(
        f"byte {i} = 0x{b:02X} near {ctx!r}" for i, b, ctx in offenders
    )


def test_sql_mode_regex_accepts_real_sql(text):
    """The SQL-mode guard must accept SELECT and WITH and reject prose.

    Extracted from the page source and translated to Python rather than
    hardcoded here, so the test follows the shipped regex instead of a copy of
    what it was supposed to be.
    """
    m = re.search(r'MODE==="raw-sql" && !/(?P<body>\^.+?)/i\.test\(v\)', text)
    assert m, "could not find the SQL-mode guard in web/index.html"
    pattern = re.compile(m.group("body").replace("\\s", r"\s").replace("\\b", r"\b"),
                         re.IGNORECASE)

    for accepted in ("SELECT 1",
                     "SELECT * FROM information_schema.tables",
                     "  select facility_name from gold_hospital_profile",
                     "WITH x AS (SELECT 1) SELECT * FROM x"):
        assert pattern.match(accepted), f"SQL mode would wrongly reject {accepted!r}"

    for rejected in ("Which hospitals deliver the best value?",
                     "selective care coordination question",
                     "how many patients have hypertension"):
        assert not pattern.match(rejected), f"SQL mode would wrongly accept {rejected!r}"


def test_every_nav_button_has_a_matching_view(text):
    """A nav entry pointing at a missing section renders a blank page.

    show() toggles `.view` sections by id `v-<name>` against `nav button`
    data-v attributes; the two lists must agree.
    """
    nav = set(re.findall(r'<button data-v="([a-z-]+)"', text))
    views = set(re.findall(r'<section class="view[^"]*" id="v-([a-z-]+)"', text))
    assert nav, "no nav buttons found"
    assert nav == views, f"nav/view mismatch -- nav only: {nav - views}, views only: {views - nav}"


def test_queue_badge_is_hidden_when_empty(text):
    """`.qbadge` sets an explicit `display`, which beats the user-agent
    [hidden]{display:none}. Without an explicit override the badge paints a
    permanent "0" on an empty queue."""
    assert ".qbadge[hidden]" in text, "the qbadge needs an explicit [hidden] display rule"


def test_proposal_block_sets_its_own_colour(text):
    """The global `pre` rule pairs light text with a dark background. `.prop`
    overrides the background to a light card, so it must set `color` too or the
    proposal a reviewer has to read becomes light-on-light."""
    m = re.search(r"\.prop\{([^}]*)\}", text, re.S)
    assert m, ".prop rule not found"
    body = m.group(1)
    assert "background" in body and "color:" in body, (
        ".prop overrides the background, so it must also set an explicit color"
    )
