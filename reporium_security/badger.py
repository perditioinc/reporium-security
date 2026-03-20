"""Update security badge on target repo README using regex pattern replacement."""

from __future__ import annotations

import re
from pathlib import Path

from reporium_security.scanner import SecurityGrade

# Badge pattern for perditio-badges block
BADGE_PATTERN = re.compile(
    r"(<!--\s*perditio-badges:security\s*-->).*?(<!--\s*/perditio-badges:security\s*-->)",
    re.DOTALL,
)

GRADE_COLORS: dict[str, str] = {
    "A": "brightgreen",
    "B": "green",
    "C": "yellow",
    "D": "orange",
    "F": "red",
}


def _badge_url(grade: SecurityGrade) -> str:
    """Generate a shields.io badge URL for the given grade."""
    color = GRADE_COLORS.get(str(grade), "lightgrey")
    return f"https://img.shields.io/badge/security-{grade}-{color}"


def _badge_markdown(grade: SecurityGrade) -> str:
    """Generate markdown badge for the given grade."""
    url = _badge_url(grade)
    return f"![Security Grade: {grade}]({url})"


def update_readme_badge(readme_path: Path, grade: SecurityGrade) -> bool:
    """Update the security badge in a README file.

    Looks for a perditio-badges:security comment block and replaces its content.
    Returns True if the badge was updated, False if no badge block was found.
    """
    if not readme_path.exists():
        return False

    content = readme_path.read_text(encoding="utf-8")
    badge_md = _badge_markdown(grade)

    replacement = (
        r"\1\n"
        + badge_md
        + r"\n\2"
    )

    new_content, count = BADGE_PATTERN.subn(
        f"<!-- perditio-badges:security -->\n{badge_md}\n<!-- /perditio-badges:security -->",
        content,
    )

    if count == 0:
        return False

    readme_path.write_text(new_content, encoding="utf-8")
    return True
