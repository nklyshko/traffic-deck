"""Interactive terminal prompts shared by the capture CLIs: arrow-key selectors,
multi-select, free text, and yes/no — built on questionary. Aborting a prompt
(Ctrl-C / Esc) raises SystemExit so callers never proceed on a half-made choice.

questionary's prompt_toolkit backend asks the terminal for cursor-position reports
(CPR) and waits/wedges when the terminal doesn't answer — which some terminals,
notably IDE-integrated ones, don't. ``PROMPT_TOOLKIT_NO_CPR=1`` tells prompt_toolkit
to skip the CPR request entirely (the cursor is assumed at column 0, which holds since
our prompts start on a fresh line), so the arrow-key UI works everywhere without the
hang or the "terminal doesn't support CPR" warning.

Choices are either plain strings, or ``(label, value)`` tuples when the displayed
label differs from the value returned.
"""

from __future__ import annotations

import os
from typing import Sequence

import questionary

# prompt_toolkit reads this when deciding whether to request CPR (at render time);
# set before any prompt runs. setdefault so an explicit override still wins.
os.environ.setdefault("PROMPT_TOOLKIT_NO_CPR", "1")


def _ask(question):
    answer = question.ask()
    if answer is None:  # Ctrl-C / Esc
        raise SystemExit("cancelled")
    return answer


def _to_choices(choices: Sequence, checked: Sequence = ()):
    checked = set(checked)
    out = []
    for c in choices:
        if isinstance(c, tuple):
            out.append(questionary.Choice(title=c[0], value=c[1], checked=c[1] in checked))
        elif c in checked:
            out.append(questionary.Choice(title=c, value=c, checked=True))
        else:
            out.append(c)
    return out


def select(message: str, choices: Sequence, default=None):
    """Single arrow-key selection; returns the chosen value."""
    kwargs = {}
    if default is not None:
        kwargs["default"] = default
    return _ask(questionary.select(message, choices=_to_choices(choices), **kwargs))


def checkbox(message: str, choices: Sequence, checked: Sequence = ()) -> list:
    """Multi-select (space to toggle, enter to confirm); returns chosen values ([] if
    none). `checked` pre-selects matching choice values (e.g. last run's picks)."""
    if not choices:
        return []
    return _ask(questionary.checkbox(message, choices=_to_choices(choices, checked)))


def text(message: str, default: str = "") -> str:
    """Free-text input; returns the trimmed string (or the default)."""
    return _ask(questionary.text(message, default=default)).strip()


def confirm(message: str, default: bool = True) -> bool:
    return _ask(questionary.confirm(message, default=default))
