"""Interactive terminal prompts shared by the capture CLIs: arrow-key selectors,
multi-select, free text, and yes/no — built on questionary. Aborting a prompt
(Ctrl-C / Esc) raises SystemExit so callers never proceed on a half-made choice.

Choices are either plain strings, or ``(label, value)`` tuples when the displayed
label differs from the value returned.
"""

from __future__ import annotations

from typing import Sequence

import questionary


def _ask(question):
    answer = question.ask()
    if answer is None:  # Ctrl-C / Esc
        raise SystemExit("cancelled")
    return answer


def _to_choices(choices: Sequence):
    out = []
    for c in choices:
        if isinstance(c, tuple):
            out.append(questionary.Choice(title=c[0], value=c[1]))
        else:
            out.append(c)
    return out


def select(message: str, choices: Sequence, default=None):
    """Single arrow-key selection; returns the chosen value."""
    kwargs = {}
    if default is not None:
        kwargs["default"] = default
    return _ask(questionary.select(message, choices=_to_choices(choices), **kwargs))


def checkbox(message: str, choices: Sequence) -> list:
    """Multi-select (space to toggle, enter to confirm); returns chosen values ([] if none)."""
    if not choices:
        return []
    return _ask(questionary.checkbox(message, choices=_to_choices(choices)))


def text(message: str, default: str = "") -> str:
    """Free-text input; returns the trimmed string (or the default)."""
    return _ask(questionary.text(message, default=default)).strip()


def confirm(message: str, default: bool = True) -> bool:
    return _ask(questionary.confirm(message, default=default))
