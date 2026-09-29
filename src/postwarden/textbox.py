"""Boxed text tables for command output."""
from __future__ import annotations


def box(headers: list[str] | None, rows: list[list | None], numeric: bool = True) -> list[str]:
    """A table with a border; a None row draws a separator."""
    cells = [None if row is None else ["-" if v is None else str(v) for v in row] for row in rows]
    filled = [c for c in cells if c is not None]
    every = ([headers] if headers else []) + filled
    widths = [max(len(row[i]) for row in every) for i in range(len(every[0]))]
    right = [numeric and i > 0 and all(c[i].isdigit() or c[i] == "-" or "/" in c[i] for c in filled)
             for i in range(len(widths))]
    rule = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def line(row: list[str], align: bool) -> str:
        return "| " + " | ".join(c.rjust(w) if align and r else c.ljust(w) for c, w, r in zip(row, widths, right)) + " |"
    out = [rule]
    if headers:
        out += [line(headers, False), rule]
    return out + [rule if row is None else line(row, True) for row in cells] + [rule]


def header(version: str, host: str, config: str, groups: list[list[list[str]]]) -> list[str]:
    """The box every report starts with: version and host and the configuration file, then the command's own row
    groups, each after a separator."""
    rows: list[list[str] | None] = [["postwarden", f"{version} on {host}"], ["Config", config]]
    for group in groups:
        rows += [None, *group]
    return box(None, rows, numeric=False)
