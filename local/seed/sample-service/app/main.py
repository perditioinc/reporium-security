"""Tiny sample service used by the local smoke target.

Deliberately clean of secrets so the secrets/history checks pass and the
grade is driven by the seeded vulnerable dependency (jinja2==2.11.2).
"""


def render(name: str) -> str:
    return f"hello {name}"


if __name__ == "__main__":
    print(render("world"))
